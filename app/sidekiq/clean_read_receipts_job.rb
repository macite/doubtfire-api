class CleanReadReceiptsJob
  include Sidekiq::Job
  include LogHelper

  def perform
    TaskComment.delete_unneeded_read_receipts
  rescue StandardError => e # to raise error message to avoid unnecessary retry
    logger.error e
  end
end
