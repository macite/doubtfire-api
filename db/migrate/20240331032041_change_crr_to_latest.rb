class ChangeCrrToLatest < ActiveRecord::Migration[7.1]
  def change
    # The subquery is used to get the last comment read by each user on each task
    subquery = CommentsReadReceipts.joins(task_comment: :task).group(:user_id,"tasks.id").select(:user_id, "MAX(task_comment_id) as max_task_comment_id", 'tasks.id as tid').to_sql

    # Sq2 is used to get the read receipts that are not the last read receipt for each user on each task
    sq2 = Task.joins(comments: :comments_read_receipts).joins("INNER JOIN (#{subquery}) as subquery ON tasks.id = subquery.tid AND comments_read_receipts.user_id = subquery.user_id").select("comments_read_receipts.id as crr_id").where("comments_tasks.id < subquery.max_task_comment_id").to_sql

    # Delete the read receipts that are not the last read receipt for each user on each task
    CommentsReadReceipts.where("id in (#{sq2})").delete_all

    TaskComment.delete_unneeded_read_receipts
  end
end
