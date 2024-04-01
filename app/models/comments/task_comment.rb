# frozen_string_literal: true

require 'tempfile'

class TaskComment < ApplicationRecord
  include MimeCheckHelpers
  include TimeoutHelper
  include FileHelper
  include AuthorisationHelpers

  belongs_to :task, optional: false # Foreign key
  belongs_to :user, optional: false
  has_one :unit, through: :task
  has_one :project, through: :task

  belongs_to :recipient, class_name: 'User', optional: false

  has_many :comments_read_receipts, class_name: 'CommentsReadReceipts', dependent: :destroy, inverse_of: :task_comment

  # Can optionally be a reply to a comment
  belongs_to :task_comment, optional: true

  validates :task, presence: true
  validates :user, presence: true
  validates :recipient, presence: true
  validates :comment, length: { minimum: 0, maximum: 4095, allow_blank: true }
  validate :valid_reply_to?, on: :create

  def self.task_has_extension_requests_subquery
    TaskComment
      .where('task_comments.date_extension_assessed IS NULL')
      .where('task_comments.type = "ExtensionComment"')
      .select(
        'COUNT(task_comments.task_id) as num_extensions',
        'task_comments.task_id as task_id'
      )
      .group('task_comments.task_id')
      .to_sql
  end

  def self.exclude_tutor_read_comments_subquery
    CommentsReadReceipts
      .joins(task_comment: { task: { task_definition: :tutorial_stream } })
      .joins("LEFT OUTER JOIN projects ON projects.id = tasks.project_id")
      .joins("LEFT OUTER JOIN tutorial_enrolments ON tutorial_enrolments.project_id = projects.id")
      .joins("LEFT OUTER JOIN tutorials ON tutorials.id = tutorial_enrolments.tutorial_id AND (tutorials.tutorial_stream_id = tutorial_streams.id OR (tutorial_streams.id IS NULL))")
      .joins("LEFT OUTER JOIN unit_roles ON tutorials.unit_role_id = unit_roles.id")
      .joins("LEFT OUTER JOIN users ON users.id = unit_roles.user_id")
      .select("MAX(task_comments.id) as task_comment_id, tasks.id as task_id, users.id as user_id")
      .group("comments_read_receipts.user_id", "tasks.id")
      .where('comments_read_receipts.user_id = users.id')
      .to_sql
  end

  def self.num_comments_unread_by_user_subquery(user, exclude_tutor_read_comments, groups = false)
    last_read_by_user_subquery = CommentsReadReceipts # All read receipts
                                 .select('MAX(task_comment_id) as task_comment_id', 'task_id as task_id', 'user_id as user_id') # Get last comment and task
                                 .group('task_id', 'user_id') # By task
                                 .to_sql

    last_read_by_tutor_subquery = if exclude_tutor_read_comments
                                    TaskComment.exclude_tutor_read_comments_subquery
                                  else
                                    CommentsReadReceipts # All read receipts
                                      .select('MAX(task_comment_id) as task_comment_id', 'task_id as task_id', 'user_id as user_id') # Get last comment and task
                                      .where("comments_read_receipts.user_id = :uid", uid: user.id)
                                      .group('task_id', 'user_id') # By task
                                      .to_sql
                                  end

    TaskComment
      .joins('JOIN tasks my_tasks ON my_tasks.id = task_comments.task_id')
      .joins("LEFT OUTER JOIN (#{last_read_by_user_subquery}) crr ON crr.task_id = task_comments.task_id AND crr.user_id = #{user.id}") # last read by user
      .joins("LEFT OUTER JOIN (#{last_read_by_tutor_subquery}) crr2 ON crr2.task_id = task_comments.task_id") # last read by tutor recipient
      .where('task_comments.type IS NULL OR task_comments.type <> "TaskStatusComment"')
      .select(
        # 'task_comments.id as id',
        # 'task_comments.task_id as task_id',
        # 'crr.user_id as crr_uid',
        # 'crr.task_comment_id as last_read_by_user',
        # 'crr2.task_comment_id as last_read_by_tutor',
        (groups ? 'my_tasks.group_submission_id as group_submission_id' : 'task_comments.task_id as task_id'),
        'SUM(CASE WHEN (crr.task_comment_id IS NULL OR crr.task_comment_id < task_comments.id) AND (crr2.task_comment_id IS NULL OR crr2.task_comment_id < task_comments.id) THEN 1 ELSE 0 END) as number_unread'
      )
      .group((groups ? 'my_tasks.group_submission_id' : 'task_comments.task_id'))
      .having("NOT #{groups ? 'my_tasks.group_submission_id' : 'task_comments.task_id'} IS NULL")
      .to_sql
  end

  def self.delete_unneeded_read_receipts
    # Keep only the read receipts for the recipient - when possible

    # Subquery lists the task id and user id for each task that has a teaching staff member
    task_teaching_staff_subquery = Task
                                   .joins(project: {unit: { unit_roles: :user}})
                                   .select("tasks.id as task_id", "users.id as user_id").to_sql

    CommentsReadReceipts
      .joins('JOIN task_comments my_task_comments ON my_task_comments.id = comments_read_receipts.task_comment_id')
      .joins("JOIN (#{TaskComment.exclude_tutor_read_comments_subquery}) crr2 ON my_task_comments.task_id = crr2.task_id")
      .joins("JOIN (#{task_teaching_staff_subquery}) ttss ON ttss.task_id = my_task_comments.task_id AND ttss.user_id = comments_read_receipts.user_id")
      .select('my_task_comments.task_id as tid', 'crr2.user_id as user_id', 'my_task_comments.id as tcid','comments_read_receipts.user_id as uid, ttss.user_id as ttss_user_id')
      .where('crr2.user_id <> comments_read_receipts.user_id')
      .where('crr2.task_comment_id >= comments_read_receipts.task_comment_id')
      .delete_all
  end

  # After create, mark as read by user creating
  after_create do
    mark_as_read(self.user)
  end

  # Delete action - before dependent association
  before_destroy :delete_associated_files

  def valid_reply_to?
    if reply_to_id.present?
      originalTaskComment = TaskComment.find(reply_to_id)
      replyProject = originalTaskComment.project
      errors.add(:task_comment, "Not a reply to a valid task comment") unless originalTaskComment.present?
      errors.add(:task_comment, "Original comment is not in this task") unless task.all_comments.find(reply_to_id).present?
      errors.add(:task_comment, "Not authorised to reply to comment") unless authorise?(user, originalTaskComment.project, :get) || (task.group_task? && task.group.role_for(user) != nil)
    end
  end

  def delete_associated_files
    FileUtils.rm_f attachment_path
  end

  def serialize(user, last_id = id)
    {
      id: self.id,
      comment: self.comment,
      has_attachment: ["audio", "image", "pdf"].include?(self.content_type),
      type: self.content_type || "text",
      is_new: self.new_for?(user),
      reply_to_id: self.reply_to_id,
      author: {
        id: self.user.id,
        first_name: self.user.first_name,
        last_name: self.user.last_name,
        email: self.user.email
      },
      recipient: {
        id: self.recipient.id,
        first_name: self.recipient.first_name,
        last_name: self.recipient.last_name,
        email: self.recipient.email
      },
      created_at: self.created_at,
      recipient_read: last_id && id <= last_id,
    }
  end

  def read_receipt_for(user)
    crr = CommentsReadReceipts
          .joins(:task_comment) # need to find receipt for comments for this task
          .where(user: user)
          .where('task_comments.task_id = ?', task_id)
          .last
  end

  def create_comment_read_receipt_entry(user)
    # Search for the related comment read receipt
    crr = read_receipt_for(user)

    if crr.nil?
      crr = CommentsReadReceipts.find_or_create_by(user: user, task_comment: self, task: task)
    else
      crr.update(created_at: Time.now, task_comment: self)
    end
  end

  def comment
    return 'audio comment' if content_type == 'audio'
    return 'image comment' if content_type == 'image'
    return 'pdf document' if content_type == 'pdf'
    return 'discussion comment' if content_type == 'discussion'

    super
  end

  def attachment_path
    FileHelper.comment_attachment_path(self, attachment_extension)
  end

  def attachment_file_name
    "comment-#{id}#{attachment_extension}"
  end

  def add_attachment(file_upload)
    if content_type == 'audio'
      # On upload all audio comments are converted to wav
      temp = Tempfile.new(['comment', '.wav'])
      return false unless process_audio(file_upload["tempfile"].path, temp.path)

      self.attachment_extension = '.wav'
      save
      FileUtils.mv temp.path, attachment_path
    elsif content_type == 'image'
      self.attachment_extension = if mime_type(file_upload["tempfile"].path).starts_with?('image/gif')
                                    '.gif'
                                  else
                                    '.jpg'
                                  end
      save
      FileHelper.compress_image_to_dest(file_upload["tempfile"].path, attachment_path)
    else
      self.attachment_extension = '.pdf'
      save
      FileHelper.compress_pdf(file_upload["tempfile"].path)
      FileUtils.mv file_upload["tempfile"].path, attachment_path
    end

    file_upload["tempfile"].unlink

    true
  end

  def attachment_mime_type
    if attachment_extension == '.wav'
      'audio/wav; charset:binary'
    else
      mime_type(attachment_path)
    end
  end

  def remove_comment_read_entry(user)
    CommentsReadReceipts.delete_all(user: user, task_comment: self)
  end

  def mark_as_read(user)
    return if read_by?(user) # avoid propagating if not needed

    create_comment_read_receipt_entry(user)

    if user == project.tutor_for(task.task_definition)
      # Delete all other staff read receipts for this...

      task_teaching_staff_subquery = Task
                                     .joins(project: { unit: { unit_roles: :user } })
                                     .select("tasks.id as task_id", "users.id as user_id").to_sql

      CommentsReadReceipts
        .joins(:task_comment)
        .where('task_comments.task_id = :tid', tid: task_id) # comment on the same task
        .joins("JOIN (#{task_teaching_staff_subquery}) ttss ON ttss.task_id = task_comments.task_id AND ttss.user_id = comments_read_receipts.user_id") # by a teaching staff member
        .where('comments_read_receipts.user_id <> :uid', uid: user.id) # who is not the current user
        .where('comments_read_receipts.task_comment_id <= :tcid', tcid: id) # and has read less than this comment
        .delete_all
    end
  end

  def mark_as_unread(user)
    remove_comment_read_entry(user)
  end

  def new_for?(user)
    !read_by? user
  end

  def read_by?(user)
    crr = read_receipt_for(user)
    crr.present? && crr.task_comment_id >= id
  end
end
