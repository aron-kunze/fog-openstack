require 'fog/openstack/auth/token/v2'
require 'fog/openstack/auth/token/v3'
require 'fog/openstack/auth/token/fed'
require 'fog/openstack/auth/catalog/v2'
require 'fog/openstack/auth/catalog/v3'

module Fog
  module OpenStack
    module Auth
      module Token
        attr_reader :catalog, :expires, :tenant, :token, :user, :data

        class ExpiryError < RuntimeError; end
        class StandardError < RuntimeError; end
        class URLError < RuntimeError; end

        def self.build(auth, options)
          if auth[:openstack_identity_api_version] =~ /(v)*2(\.0)*/i ||
             auth[:openstack_tenant_id] || auth[:openstack_tenant]
            token = Fog::OpenStack::Auth::Token::V2.new(auth, options)
          else
            token = Fog::OpenStack::Auth::Token::V3.new(auth, options)
          end
          if auth[:openstack_service_provider]
            service_provider = token.data["token"]["service_providers"].select{ |x| 
              x["id"] == auth["openstack_service_provider"]
            }.first
            if service_provider.present?
              token = Fog::OpenStack::Auth::Token::Fed.new({ openstack_auth_url: service_provider["sp_url"], 
                                                             openstack_auth_token: token.token })
            end
          end
          token
        end

        def initialize(auth, options)
          raise URLError, 'No URL provided' if auth[:openstack_auth_url].nil? || auth[:openstack_auth_url].empty?
          @creds = {
            :data => build_credentials(auth),
            :uri  => URI.parse(auth[:openstack_auth_url])
          }
          response = authenticate(@creds, options)
          set(response)
        end

        def get
          set(authenticate(@creds, {})) if expired?
          @token
        end

        private

        def authenticate(creds, options)
          connection = Fog::Core::Connection.new(creds[:uri].to_s, false, options)

          request = {
            :expects => [200, 201],
            :headers => {'Content-Type' => 'application/json'},
            :body    => Fog::JSON.encode(creds[:data]),
            :method  => 'POST',
            :path    => creds[:uri].path + prefix_path(creds[:uri]) + path
          }

          connection.request(request)
        end

        def expired?
          if @expires.nil? || @expires.empty?
            raise ExpiryError, 'Missing token expiration data'
          end
          Time.parse(@expires) < Time.now.utc
        end

        def refresh
          raise StandardError, "__method__ not implemented yet!"
        end
      end
    end
  end
end
