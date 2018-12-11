require 'fog/openstack/auth/token'
require 'fog/openstack/auth/name'

module Fog
  module OpenStack
    module Auth
      module Token
        class Fed
          include Fog::OpenStack::Auth::Token::V3
          def prefix_path(uri)
            uri
          end

          def path
            ''
          end
        end
      end
    end
  end
end
