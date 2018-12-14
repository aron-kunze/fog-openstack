require 'fog/openstack/auth/token/v3'
require 'fog/openstack/auth/name'

module Fog
  module OpenStack
    module Auth
      module Token
        class Fed < Fog::OpenStack::Auth::Token::V3
          def prefix_path(uri)
            ''
          end

          def path
            ''
          end
        end
      end
    end
  end
end
