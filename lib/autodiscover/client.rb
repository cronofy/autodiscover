#--
# Copyright (c) 2010-2011 WIMM Labs, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#++

require 'httpclient'
require 'nokogiri'
require 'hatchet'

module Autodiscover
  REDIRECT_LIMIT = 10  # attempts
  CONNECT_TIMEOUT_DEFAULT = 10  # seconds

  # Client objects are used to make queries to the autodiscover server, to
  # specify configuration values, and to maintain state between requests.
  class Client
    include Hatchet

    # Creates a Client object.
    #
    # The following options can be specified:
    #
    # <tt>:connect_timeout</tt>::  Number of seconds to wait when trying to establish
    #                              a connection. The default value is 10 seconds.
    # <tt>:debug_dev</tt>::        Device that debug messages and all HTTP
    #                              requests and responses are dumped to. The debug
    #                              device must respond to <tt><<</tt> for dump.
    def initialize(options={})
      @debug_dev = options[:debug_dev]

      @http = HTTPClient.new
      @http.connect_timeout = options[:connect_timeout] || CONNECT_TIMEOUT_DEFAULT
      @http.debug_dev = @debug_dev if @debug_dev

      @redirect_count = 0
    end

    # Get a Services object from an \Autodiscover server that is
    # available on an authenticated endpoint determined by the
    # specified Credentials object.
    def get_services(credentials, reset_redirect_count=true)
      @redirect_count = 0 if reset_redirect_count

      log.ndc.scope(credentials.email) do
        req_body = build_request_body credentials.email

        try_standard_secure_urls(credentials, req_body) ||
        try_standard_redirection_url(credentials, req_body) ||
        try_dns_serv_records(credentials, req_body)
      end
    end

    private

    def try_standard_secure_urls(credentials, req_body)
      response = nil
      [ "https://#{credentials.smtp_domain}/autodiscover/autodiscover.xml",
        "https://autodiscover.#{credentials.smtp_domain}/autodiscover/autodiscover.xml"
      ].each do |url|
        log.info { "Trying standard secure URL=#{url}" }
        @debug_dev << "AUTODISCOVER: trying #{url}\n" if @debug_dev
        response = try_secure_url(url, credentials, req_body)
        break if response
      end
      response
    end

    def try_standard_redirection_url(credentials, req_body)
      url = "http://autodiscover.#{credentials.smtp_domain}/autodiscover/autodiscover.xml"
      try_redirection_url(url, credentials, req_body)
    end

    def try_redirection_url(url, credentials, req_body)
      log.info { "Trying redirection URL=#{url}" }
      @debug_dev << "AUTODISCOVER: looking for redirect from #{url}\n" if @debug_dev

      response = @http.get(url) rescue nil

      unless response
        log.info { "No response received from #{url}" }
        return nil
      end

      log.info { "Status code #{response.status_code} from #{url} - Location=#{response.header['Location'].first}" }

      if response.status_code == 302
        try_redirect_url(response.header['Location'].first, credentials, req_body)
      else
        nil
      end
    end

    def try_secure_url(url, credentials, req_body)
      log.info { "Trying secure URL=#{url}" }

      begin
        @http.set_auth(url, credentials.email, credentials.password)
        response = @http.post(url, req_body, {'Content-Type' => 'text/xml; charset=utf-8'})
      rescue => e
        log.info { "Failed trying secure URL=#{url} - #{e.class} - #{e.message}" }
      end

      unless response
        log.info { "No response received from #{url}" }
        return nil
      end

      log.info { "Status code #{response.status_code} from #{url}" }
      log.debug { response.header.all.inspect }
      log.debug { response.content }

      if response.status_code == 302
        try_redirect_url(response.header['Location'].first, credentials, req_body)
      elsif HTTP::Status.successful?(response.status_code)
        result = parse_response(response.content)

        case result
        when Autodiscover::Services
          log.info { "Found services from #{url} - #{result}" }
          result

        when Autodiscover::RedirectUrl
          try_redirect_url(result.url, credentials, req_body)

        when Autodiscover::RedirectAddress
          begin
            credentials.set_domain_from_address(result.address)
          rescue ArgumentError
            log.info { "Invalid email address response from #{url} - address=#{result.address}" }
            return nil
          end

          try_redirect_addr(credentials)
        else
          log.info { "Did not recognise response from #{url} of #{result.class}" }
          nil
        end
      else
        nil
      end
    end

    def try_redirect_url(url, credentials, req_body)
      log.info { "Trying redirect URL - #{url}" }

      @redirect_count += 1

      if @redirect_count > REDIRECT_LIMIT
        log.info { "Redirect limit exceeded - redirect_count=#{@redirect_count}" }
        return nil
      end

      if url =~ /^https:/i
        # Only permit redirects to secure addresses
        try_secure_url(url, credentials, req_body)
      else
        log.info { "Ignoring unsecure URL #{url}" }
        nil
      end
    end

    def try_redirect_addr(credentials)
      log.info { "Trying redirected email=#{credentials.email}" }

      @redirect_count += 1

      if @redirect_count > REDIRECT_LIMIT
        log.info { "Redirect limit exceeded - redirect_count=#{@redirect_count}" }
        return nil
      end

      get_services(credentials, false)
    end

    SrvRecord = Struct.new(:priority, :weight, :port, :target) do
      HTTP_PORT_NUMBER = 80
      HTTPS_PORT_NUMBER = 443

      def self.parse(record)
        parts = record.split(' ')
        self.new(parts[1].to_i, parts[2].to_i, parts[3].to_i, parts[4].sub(/\.\Z/, ''))
      end

      def http?
        self.port == HTTP_PORT_NUMBER
      end

      def https?
        self.port == HTTPS_PORT_NUMBER
      end

      def <=>(other)
        self.sort_attributes <=> other.sort_attributes
      end

      def sort_attributes
        [self.port_priority, self.priority, -self.weight]
      end

      def port_priority
        if https?
          0
        else
          1
        end
      end
    end

    def try_dns_serv_records(credentials, req_body)
      log.info { "Entering #try_dns_serv_records" }

      require 'ostruct'

      output =
        begin
          `dig +trace +short -t srv _autodiscover._tcp.#{credentials.smtp_domain}`
        rescue => e
          log.warn "Error in #try_dns_serv_records smtp_domain=#{credentials.smtp_domain} - #{e.message}", e
          ''
        end

      srv_records = output.split("\n")
        .map(&:strip)
        .select { |line| line =~ /\ASRV/ }
        .map    { |line| SrvRecord.parse(line) }
        .each   { |srv| log.info { "Found #{srv.inspect}" } }
        .select { |srv| srv.https? or srv.http? }
        .sort

      response = nil
      srv_records.each do |srv|
        log.info { "Trying SRV #{srv.inspect}" }

        if srv.https?
          url = "https://#{srv.target}/autodiscover/autodiscover.xml"
          @debug_dev << "AUTODISCOVER: trying #{url}\n" if @debug_dev
          response = try_secure_url(url, credentials, req_body)
        else
          url = "http://#{srv.target}/autodiscover/autodiscover.xml"
          response = try_redirection_url(url, credentials, req_body)
        end

        break if response
      end
      response
    end

    def build_request_body(email)
      Nokogiri::XML::Builder.new do |xml|
        xml.Autodiscover('xmlns' => 'http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006') {
          xml.Request {
            xml.EMailAddress email
            xml.AcceptableResponseSchema 'http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a'
          }
        }
      end.to_xml
    end

    NAMESPACES = {
      'a' => 'http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006',
      'o' => 'http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a'
    }  #:nodoc:

    def parse_response(body)
      doc = parse_xml body

      unless doc
        log.info { "No document extracted from body" }
        return nil
      end

      # The response must include an Account element. Return an error if not found.
      account_e = doc.at_xpath('a:Autodiscover/o:Response/o:Account', NAMESPACES)
      unless account_e
        log.info { "No account element found within document" }
        return nil
      end

      log.info { "Account element contents = #{account_e}" }

      # The response must include an Action element. Return an error if not found.
      action_e = account_e.at_xpath('o:Action', NAMESPACES)
      unless action_e
        log.info { "No action email found within account" }
        return nil
      end

      case action_e.content
      when /^settings$/i
        log.info { "settings action content - #{action_e}" }
        # Response contains configuration settings in <Protocol> elements
        # Only care about about "EXPR" type protocol configuration values
        # for accessing Exchange services outside of the firewall
        settings = {}
        if protocol_e = account_e.at_xpath('o:Protocol[o:Type="EXPR"]', NAMESPACES)
          log.info { "protocol settings found - #{protocol_e}" }
          # URL for the Web services virtual directory.
          ews_url_e = protocol_e.at_xpath('o:EwsUrl', NAMESPACES)
          settings['ews_url'] = ews_url_e.content if ews_url_e
          # Time to Live (TTL) in hours. Default is 1 hour if no element is
          # returned.
          ttl_e = protocol_e.at_xpath('o:TTL', NAMESPACES)
          settings['ttl'] = ttl_e ? ttl_e.content : 1
        end
        Autodiscover::Services.new(settings)
      when /^redirectAddr$/i
        log.info { "redirectAddr action content - #{action_e}" }
        # Response contains a new address that must be used to re-­Autodiscover
        redirect_addr_e = account_e.at_xpath('o:RedirectAddr', NAMESPACES)
        address = redirect_addr_e ? redirect_addr_e.content : nil
        return nil unless address
        Autodiscover::RedirectAddress.new(address)
      when /^redirectUrl$/i
        log.info { "redirectUrl action content - #{action_e}" }
        # Response contains a new URL that must be used to re-Autodiscover
        redirect_url_e = account_e.at_xpath('o:RedirectUrl', NAMESPACES)
        url = redirect_url_e ? redirect_url_e.content : nil
        return nil unless url
        Autodiscover::RedirectUrl.new(url)
      else
        log.info { "Unhandled action content - #{action_e}" }
        nil
      end
    end

    def parse_xml(doc)
      Nokogiri::XML(doc) { |c| c.options = Nokogiri::XML::ParseOptions::STRICT }
    rescue Nokogiri::XML::SyntaxError
      nil
    end
  end

  class RedirectUrl  #:nodoc: all
    attr_reader :url

    def initialize(url)
      @url = url
    end
  end

  class RedirectAddress  #:nodoc: all
    attr_reader :address

    def initialize(address)
      @address = address
    end
  end
end
