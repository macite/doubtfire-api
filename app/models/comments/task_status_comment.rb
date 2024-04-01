class TaskStatusComment < TaskComment
  belongs_to :task_status, optional: false

  before_create do
    self.content_type = :status
  end

  after_create do
    mark_as_read(self.recipient)
  end

  def serialize(user, last_id = id)
    json = super(user, last_id)
    json[:recipient_read_time] = nil
    json[:date] = self.created_at
    json[:status] = task_status.status_key
    json
  end
end
