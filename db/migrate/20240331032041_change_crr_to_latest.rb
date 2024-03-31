class ChangeCrrToLatest < ActiveRecord::Migration[7.1]
  def change
    # The subquery is used to get the last comment read by each user on each task
    subquery = CommentsReadReceipts.joins(task_comment: :task).group(:user_id,"tasks.id").select(:user_id, "MAX(task_comment_id) as max_task_comment_id", 'tasks.id as tid').to_sql

    # Sq2 is used to get the read receipts that are not the last read receipt for each user on each task
    sq2 = Task.joins(comments: :comments_read_receipts).joins("INNER JOIN (#{subquery}) as subquery ON tasks.id = subquery.tid AND comments_read_receipts.user_id = subquery.user_id").select("comments_read_receipts.id as crr_id").where("comments_tasks.id < subquery.max_task_comment_id").to_sql

    # Delete the read receipts that are not the last read receipt for each user on each task
    CommentsReadReceipts.where("id in (#{sq2})").delete_all

    # Keep only the read receipts for the recipient - when possible

    # Subquery lists the comment read by the tutor for each task
    subquery = CommentsReadReceipts
      .joins(task_comment: {task: {task_definition: :tutorial_stream}})
      .joins("left OUTER join projects ON projects.id = tasks.project_id")
      .joins("left OUTER join tutorial_enrolments ON tutorial_enrolments.project_id = projects.id")
      .joins("left OUTER join tutorials ON tutorials.id = tutorial_enrolments.tutorial_id AND (tutorials.tutorial_stream_id = tutorial_streams.id OR tutorial_streams.id IS NULL)")
      .joins("left OUTER join unit_roles ON tutorials.unit_role_id = unit_roles.id")
      .joins("left OUTER join users ON users.id = unit_roles.user_id")
      .select("MAX(task_comments.id) as task_comment_id, tasks.id as task_id, users.id as user_id")
      .group("comments_read_receipts.user_id")
      .where('comments_read_receipts.user_id = users.id')
      .to_sql

    # Subquery lists the task id and user id for each task that has a teaching staff member
    task_teaching_staff_subquery = Task
      .joins(project: {unit: { unit_roles: :user}})
      .select("tasks.id as task_id", "users.id as user_id").to_sql

    CommentsReadReceipts
      .joins(:task_comment)
      .joins("JOIN (#{subquery}) crr2 ON task_comments_comments_read_receipts.task_id = crr2.task_id")
      .joins("JOIN (#{task_teaching_staff_subquery}) ttss ON task_comments_comments_read_receipts.task_id = task_comments_comments_read_receipts.task_id AND ttss.user_id = comments_read_receipts.user_id")
      .select('task_comments_comments_read_receipts.task_id as tid', 'crr2.user_id as user_id', 'task_comments_comments_read_receipts.id as tcid','comments_read_receipts.user_id as uid, ttss.user_id as ttss_user_id')
      .where('crr2.user_id <> comments_read_receipts.user_id')
      .where('crr2.task_comment_id >= comments_read_receipts.task_comment_id')
      .delete_all
  end
end
