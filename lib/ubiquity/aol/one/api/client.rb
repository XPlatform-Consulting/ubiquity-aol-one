require 'cgi'
require 'json'
require 'logger'
require 'net/http'
require 'uri'
require 'xmlsimple'

module Ubiquity

  module AOL

    module O2

      module API

        class Client

          class HTTPClient

            attr_accessor :logger, :http, :http_host_address, :http_host_port, :base_uri
            attr_accessor :username, :password

            attr_accessor :default_request_headers,
                          :default_company_id

            attr_accessor :log_request_body, :log_response_body, :log_pretty_print_body

            attr_accessor :request, :response

            DEFAULT_HTTP_HOST_ADDRESS = 'api.vidible.tv'
            DEFAULT_HTTP_HOST_PORT = 80

            DEFAULT_BASE_PATH = ''

            DEFAULT_HEADER_CONTENT_TYPE = 'application/json; charset=utf-8'
            DEFAULT_HEADER_ACCEPTS = 'application/json'

            def initialize(args = { })
              args = args.dup
              initialize_logger(args)
              initialize_http(args)

              logger.debug { "#{self.class.name}::#{__method__} Arguments: #{args.inspect}" }

              # @username = args[:username] || DEFAULT_USERNAME
              # @password = args[:password] || DEFAULT_PASSWORD

              @base_uri = args[:base_uri] || "http#{http.use_ssl? ? 's' : ''}://#{http.address}:#{http.port}"
              @default_base_path = args[:default_base_path] || DEFAULT_BASE_PATH

              @default_company_id = args[:default_company_id] || args[:company_id]

              # @user_agent_default = "#{@hostname}:#{@username} Ruby SDK Version #{Vidispine::VERSION}"

              # @authorization_header_key ||= 'Authorization' #CaseSensitiveHeaderKey.new('Authorization')
              # @authorization_header_value ||= %(Basic #{["#{username}:#{password}"].pack('m').delete("\r\n")})

              content_type = args[:content_type_header] ||= DEFAULT_HEADER_CONTENT_TYPE
              accepts = args[:accepts_header] ||= args[:accept_header] || DEFAULT_HEADER_ACCEPTS

              @default_request_headers = {
                  'Content-Type' => content_type,
                  'Accept' => accepts,
                  # authorization_header_key => authorization_header_value,
              }

              @log_request_body = args.fetch(:log_request_body, true)
              @log_response_body = args.fetch(:log_response_body, true)
              @log_pretty_print_body = args.fetch(:log_pretty_print_body, true)

              @parse_response = args.fetch(:parse_response, true)
            end

            def initialize_logger(args = { })
              @logger = args[:logger] ||= Logger.new(args[:log_to] || STDOUT)
              log_level = args[:log_level]
              if log_level
                @logger.level = log_level
                args[:logger] = @logger
              end
              @logger
            end

            def initialize_http(args = { })
              @http_host_address = args[:http_host_address] ||= DEFAULT_HTTP_HOST_ADDRESS
              @http_host_port = args[:http_host_port] ||= DEFAULT_HTTP_HOST_PORT
              @http = Net::HTTP.new(http_host_address, http_host_port)

              http
            end

            # Formats a HTTPRequest or HTTPResponse body for log output.
            # @param [HTTPRequest|HTTPResponse] obj
            # @return [String]
            def format_body_for_log_output(obj)
              if obj.content_type == 'application/json'
                if @log_pretty_print_body
                  _body = obj.body
                  output = JSON.pretty_generate(JSON.parse(_body)) rescue _body
                  return output
                else
                  return obj.body
                end
              elsif obj.content_type == 'application/xml'
                return obj.body
              else
                return obj.body.inspect
              end
            end

            # @param [HTTPRequest] request
            def send_request(request, options = { })
              _http = options[:http] || http
              return_response = options.fetch(:return_response, false)
              _parse_response = options.fetch(:parse_response, @parse_response)
              @response_parsed = nil
              @request = request
              logger.debug { %(REQUEST: #{request.method} http#{_http.use_ssl? ? 's' : ''}://#{_http.address}:#{http.port}#{request.path} HEADERS: #{request.to_hash.inspect} #{log_request_body and request.request_body_permitted? ? "\n-- BODY BEGIN --\n#{format_body_for_log_output(request)}\n-- BODY END --" : ''}) }

              @response = _http.request(request)
              logger.debug { %(RESPONSE: #{response.inspect} HEADERS: #{response.to_hash.inspect} #{log_response_body and response.respond_to?(:body) ? "\n-- BODY BEGIN --\n#{format_body_for_log_output(response)}\n-- BODY END--" : ''}) }

              return @response if return_response
              _parse_response ? response_parsed : response.body
            end

            def response_parsed
              @response_parsed ||= begin
                logger.debug { "Parsing Response. #{response.body.inspect}" }

                case response.content_type
                  when 'application/json'
                    JSON.parse(response.body) rescue response
                  when 'text/xml'
                    XmlSimple.xml_in(response.body, 'forcearray' => false)
                  else
                    response.body
                end
              end
            end

            # @param [String] path
            # @param [Hash|String|Nil] query
            # @return [URI]
            def build_uri(path = '', query = nil, company_id = nil)
              _query = query.is_a?(Hash) ? query.map { |k,v| "#{CGI.escape(k.to_s)}=#{CGI.escape(v.respond_to?(:to_s) ? v.to_s : v)}" }.join('&') : query
              _path = "#{path}#{_query and _query.respond_to?(:empty?) and !_query.empty? ? "?#{_query}" : ''}"
              _base_uri = company_id ? File.join(base_uri, company_id) : base_uri
              URI.parse(File.join(_base_uri, _path))
            end

            if RUBY_VERSION.start_with? '1.8.'
              def request_method_name_to_class_name(method_name)
                method_name.to_s.capitalize
              end
            else
              def request_method_name_to_class_name(method_name)
                method_name.to_s.capitalize.to_sym
              end
            end

            # @param [Symbol] method_name (:get)
            # @param [Hash] args
            # @option args [Hash] :headers ({})
            # @option args [String] :path ('')
            # @option args [Hash] :query ({})
            # @option args [Any] :body (nil)
            # @param [Hash] options
            # @option options [Hash] :default_request_headers (@default_request_headers)
            def call_method(method_name = :get, args = { }, options = { })
              headers = args[:headers] || options[:headers] || { }
              path = args[:path] || ''
              query = args[:query] || options[:query] || { }
              body = args[:body]
              company_id = args.fetch(:company_id, options.fetch(:company_id, default_company_id))

              # Allow the default request headers to be overridden
              _default_request_headers = options.fetch(:default_request_headers, default_request_headers)
              _default_request_headers ||= { }
              _headers = _default_request_headers.merge(headers)

              @uri = build_uri(path, query, company_id)
              klass_name = request_method_name_to_class_name(method_name)
              klass = Net::HTTP.const_get(klass_name)

              request = klass.new(@uri.request_uri, _headers)

              if request.request_body_permitted?
                _body = (body and !body.is_a?(String)) ? JSON.generate(body) : body
                logger.debug { "Processing Body: '#{_body}'" }
                request.body = _body if _body
              end

              send_request(request)
            end

            def delete(path, options = { })
              args = { :path => path }
              call_method(:delete, args, options)
            end

            def get(path, options = { })
              args = { :path => path }
              call_method(:get, args, options)
            end

            def head(path, options = { })
              args = { :path => path }
              call_method(:head, args, options)
            end

            def options(path, options = { })
              args = { :path => path }
              call_method(:options, args, options)
            end

            def put(path, body, options = { })
              args = { :path => path, :body => body }
              call_method(:put, args, options)
            end

            def post(path, body, options = { })
              args = { :path => path, :body => body }
              call_method(:post, args, options)
            end

            # HTTPClient
          end

          attr_accessor :http_client, :request, :response, :logger

          def initialize(args = { })
            @http_client = HTTPClient.new(args)
            @logger = http_client.logger
          end

          # def process_request(request, options = nil)
          #   @response = nil
          #   @request = request
          #   request.client = self unless request.client
          #   options ||= request.options
          #   logger.warn { "Request is Missing Required Arguments: #{request.missing_required_arguments.inspect}" } unless request.missing_required_arguments.empty?
          #   @response = http_client.call_method(request.http_method, { :path => request.path, :query => request.query, :body => request.body }, options)
          # end
          #
          # def process_request_using_class(request_class, args, options = { })
          #   @response = nil
          #   @request = request_class.new(args, options.merge(:client => self))
          #   process_request(request, options)
          # end

          class Response

            attr_reader :body, :success, :data, :message

            def initialize(http_response, options = { })
              @code = http_response.code
              @body = http_response.body

              # Convert Success to a boolean instead of a string
              @success = (body['success'] == 'true')
              body['success'] = success if body.has_key?('success')

              @data = body['data']
              @message = body['message']
            end

            def [](key)
              instance_variable_get("@#{key}")
            end

            def success?; @success end

            def to_hash; body end
            def inspect; body.inspect end
            def to_s; body.inspect end

          end


          DEFAULT_PARAMETER_SEND_IN_VALUE = :body

          def self.normalize_argument_hash_keys(hash)
            return hash unless hash.is_a?(Hash)
            Hash[ hash.dup.map { |k,v| [ normalize_parameter_name(k), v ] } ]
          end

          def self.normalize_parameter_name(name)
            name.respond_to?(:to_s) ? name.to_s.gsub('_', '').gsub('-', '').downcase : name
          end

          # A method to expose parameter processing
          #
          # @param [Hash|Symbol] param The parameter to process
          # @param [Hash] args ({ }) Arguments to possibly match to the parameter
          # @param [Hash] args_out ({ }) The processed value of the parameter (if any)
          # @param [Array] missing_required_arguments ([ ]) If the parameter was required and no argument found then it
          # will be placed into this array
          # @param [Hash] processed_parameters ({ }) The parameter will be placed into this array once processed
          # @param [Symbol] default_parameter_send_in_value (DEFAULT_PARAMETER_SEND_IN_VALUE) The :send_in value that
          # will be set if the :send_in key is not found
          # @param [Hash] options
          # @option options [True|False] :normalize_argument_hash_keys (false)
          def self.process_parameter(param, args = { }, args_out = { }, missing_required_arguments = [ ], processed_parameters = { }, default_parameter_send_in_value = DEFAULT_PARAMETER_SEND_IN_VALUE, options = { })
            args = normalize_argument_hash_keys(args) || { } if options.fetch(:normalize_argument_hash_keys, false)

            _k = param.is_a?(Hash) ? param : { :name => param, :required => false, :send_in => default_parameter_send_in_value }
            _k[:send_in] ||= default_parameter_send_in_value

            proper_parameter_name = _k[:name]
            param_name = normalize_parameter_name(proper_parameter_name)
            arg_key = (has_key = args.has_key?(param_name)) ?
                          param_name :
                          ( (_k[:aliases] || [ ]).map { |a| normalize_parameter_name(a) }.find { |a| has_key = args.has_key?(a) } || param_name )

            value = has_key ? args[arg_key] : _k[:default_value]
            is_set = has_key || _k.has_key?(:default_value)

            processed_parameters[proper_parameter_name] = _k.merge(:value => value, :is_set => is_set)

            unless is_set
              missing_required_arguments << proper_parameter_name if _k[:required]
            else
              args_out[proper_parameter_name] = value
            end

            { :arguments_out => args_out, :processed_parameters => processed_parameters, :missing_required_arguments => missing_required_arguments }
          end

          # A method to expose parameter processing
          #
          # @param [Hash|Symbol] param The parameter to process
          # @param [Hash] args ({ }) Arguments to possibly match to the parameter
          # @param [Hash] args_out ({ }) The processed value of the parameter (if any)
          # @param [Array] missing_required_arguments ([ ]) If the parameter was required and no argument found then it
          # will be placed into this array
          # @param [Hash] processed_parameters ({ }) The parameter will be placed into this array once processed
          # @param [Symbol] default_parameter_send_in_value (DEFAULT_PARAMETER_SEND_IN_VALUE) The :send_in value that
          # will be set if the :send_in key is not found
          # @param [Hash] options
          # @option options [True|False] :normalize_argument_hash_keys (false)
          def self.process_parameters(params, args, options = { })
            args = normalize_argument_hash_keys(args) || { }
            args_out = options[:arguments_out] || { }
            default_parameter_send_in_value = options[:default_parameter_send_in_value] || DEFAULT_PARAMETER_SEND_IN_VALUE
            processed_parameters = options[:processed_parameters] || { }
            missing_required_arguments = options[:missing_required_arguments] || [ ]
            { :arguments_out => args_out, :processed_parameters => processed_parameters, :missing_required_arguments => missing_required_arguments }
            params.each do |param|
              process_parameter(param, args, args_out, missing_required_arguments, processed_parameters, default_parameter_send_in_value)
            end

            { :arguments_out => args_out,
              :processed_parameters => processed_parameters,
              :missing_required_arguments => missing_required_arguments }
          end

          def process_parameters(*args)
            self.class.process_parameters(*args)
          end

          # Exposes HTTP Methods
          # @example http(:get, '/')
          def http(method, *args)
            @request = nil
            begin
              @response = http_client.__send__(method, *args)
            ensure
              @request = http_client.request
            end
            # Response.new(response)
            @response
          end

          # ##################################
          # @!group API Methods

          # @param [Hash] args
          # @option args [String] :company_key
          # @option args [Hash] :payload The body of the request
          def video_create(args = { }, options = { })
            params = [
                { :name => :company_key, :send_in => :path },
                :payload
            ]
            param_data = process_parameters(params, args)
            args_out = param_data[:arguments_out]

            company_key = args_out.delete(:company_key) { }
            payload = args_out.delete(:payload) { }

            options[:company_id] = nil
            http(:post, "#{company_key}/video", payload, options)
          end

          # Creates a Video Record that links to the external videoURL specified
          #
          # See "Advanced Create Request" section on the following page:
          # @see http://support.vidible.tv/hc/en-us/articles/207791606-Create-Video-Upload-
          # @see http://help.aolonnetwork.com/hc/en-us/articles/209634233-Create-Video-Upload-
          def video_add_external(args = { }, options = { })
            video_create(args, options)
          end
          alias :video_create_external :video_add_external


          # Triggers an ingest of a video from S3
          #
          # @see http://help.aolonnetwork.com/hc/en-us/article_attachments/203085749/S3_Import_Tool_Implementation_Guide_V.1.2.pdf
          # @see http://s3import.vidible.tv/
          def video_import_from_s3(args = { }, options = { })
            params = [
                { :name => :company_id, :default_value => http_client.default_company_id },
                :bucket_name,
                :object_key,
                { :name => :host_address, :default_value => 'videoimportapi.vidible.tv' }
            ]

            param_data = process_parameters(params, args)
            args_out = param_data[:arguments_out]

            bucket_name = args_out[:bucket_name]
            object_key = args_out[:object_key]
            company_id = args_out[:company_id]

            host_address = args_out[:host_address]

            path = "/import?cid=#{company_id}&assetBucket=#{bucket_name}&assetKey=#{CGI.escape(object_key)}"

            http = Net::HTTP.new(host_address)
            headers = { 'Content-Type' => 'application/json', 'Accept' => '*/*' }
            request = Net::HTTP::Post.new(path, headers)

            http_client.send_request(request, { :http => http, :parse_response => false }.merge(options))
          end

          def video_search(args = { }, options = { })
            params = [
                { :name => :bcid, :aliases => [ :company_id ], :default_value => http_client.default_company_id },
                :query,
                :pid,
                :offset,
                :limit,
                :transcript,
                :sort,
                :ascending,
            ]
            param_data = process_parameters(params, args)
            args_out = param_data[:arguments_out]


            http(:get, 'search', { :query => args_out, :company_id => nil }.merge(options))
          end

          # @!endgroup API Methods
          # ##################################

          # Client
        end

        # API
      end

      # One
    end

    # AOL
  end

  # Ubiquity
end
