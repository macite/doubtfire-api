class AddTags < ActiveRecord::Migration
  def change
    add_column :projects, :tags, :string
    add_column :task_definitions, :tags, :string
    add_column :units, :tags, :string
  end
end
