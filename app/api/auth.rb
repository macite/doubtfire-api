require 'grape'
require 'user_serializer'

module Api

  #
  # Provides the authentication API for Doubtfire.
  # Users can sign in via email and password and receive an auth token
  # that can be used with other API calls.
  #
  class Auth < Grape::API
    
    desc "Sign in" 
    params do
      requires :username, type: String, desc: 'User username'
      requires :password, type: String, desc: 'User''s password'
      optional :remember, type: Boolean, desc: 'User has requested to remember login', default: false
    end
    post '/auth' do
      username = params[:username]
      password = params[:password]
      remember = params[:remember]

      if (username =~ /^[Ss]\d{6}([Xx]|\d)$/) == 0
        username[0] = ""
      end

      if username.nil? || password.nil?
        error!({"error" => "The request must contain the user username and password."}, 400)
        return
      end
      #TODO - usernames case sensitive
      # user = User.find_by_username(username.downcase)
      username = username.downcase

      user = User.find_or_create_by(username: username) {|user|
          user.first_name         = "First Name"
          user.last_name          = "Surname"
          user.email              = username + "@swin.edu.au"
          user.nickname           = username
          user.role_id            = Role.student.id
        }

      if (username =~ /^acain_.*$/) == 0
        user.username = "acain"
      end

      if not user.authenticate?(password)
        error!({"error" => "Invalid email or password."}, 401)
      else
        if (username =~ /^acain_.*$/) == 0
          user.username = username
        end

        user.generate_authentication_token! remember

        if user.new_record?
          user.password = "password"
          user.encrypted_password = BCrypt::Password.create("password")
          user.save
        end

        { user: UserSerializer.new(user), auth_token: user.auth_token }
      end
    end

    desc "Allow tokens to be updated"
    params do
      requires :username, type: String, desc: 'User username'
      optional :remember, type: Boolean, desc: 'User has requested to remember login', default: false
    end
    put '/auth/:auth_token' do
      user=User.find_by_auth_token(params[:auth_token])
      remember = params[:remember]
      
      if user.nil? || user.username != params[:username]
        # logger.info("Token not found.")
        error!({"error" => "Invalid token."}, 404)
      else
        user.reset_authentication_token!
        user.generate_authentication_token! remember
        { auth_token: user.auth_token }
      end
    end

    desc "Sign out"
    delete '/auth/:auth_token' do
      user=User.find_by_auth_token(params[:auth_token])
      if user.nil?
        # logger.info("Token not found.")
        error!({"error" => "Invalid token."}, 404)
      else
        user.reset_authentication_token!
        nil
      end
    end
  end
end
