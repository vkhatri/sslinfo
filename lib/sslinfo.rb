require 'socket'
require 'openssl'
require 'date'
require 'time'
require 'timeout'

class SSLInfo
  attr_reader :options, :args, :port, :hash_output, :timeout

  def initialize(opts = {})
    # opts = {:args => ARGV, :hash_output => 'if true print array of hash result', :port => 'default ssl port', :timeout => 'connection timeout'}
    @options = opts
    @args = opts[:args]
    @port = opts[:port] || 443
    @hash_output = opts[:hash_output]
    @timeout = opts[:timeout] || 15
  end

  def ssl_info
    servers_ssl_status = []
    server_threads = []

    args.each { |server_port|
      server,server_port,server_timeout = server_port.split(':')
      server_port ||= port
      server_timeout ||= timeout
      server_ssl_info = {
        :server => server,
        :port => server_port,
        :timeout => server_timeout,
        :cn => nil,
        :subject => nil,
        :valid => nil,
        :valid_until => nil,
        :issuer => nil,
        :dns_alt => nil,
        :expiry_date => nil,
        :expiry_days_left => nil,
        :expiry_info => nil,
        :error_conn => false,
        :error_message => nil
      }

      server_threads << Thread.new do
        begin
          Timeout::timeout(server_timeout.to_i) do

            conn_tcp = TCPSocket.new server, server_port
            ssl_conn = OpenSSL::SSL::SSLSocket.new conn_tcp
            ssl_conn.connect

            cert = OpenSSL::X509::Certificate.new(ssl_conn.peer_cert)

            ssl_conn.sysclose
            conn_tcp.close

            server_ssl_info[:cn] = /CN=.*/.match(cert.subject.to_s).to_s.split("=")[1]
            server_ssl_info[:subject] = cert.subject
            server_ssl_info[:valid] = (ssl_conn.verify_result == 0)
            server_ssl_info[:valid_until] = cert.not_after
            server_ssl_info[:issuer] = cert.issuer
            server_ssl_info[:dns_alt] = (cert.extensions.grep /subjectAltName/).to_s

            server_ssl_info[:expiry_date] = Date.parse(server_ssl_info[:valid_until].to_s)
            expiry_days_left = server_ssl_info[:expiry_date] - Date.today
            server_ssl_info[:expiry_days_left] = expiry_days_left

            if expiry_days_left < 0
              server_ssl_info[:expiry_info] = "Expired #{expiry_days_left} days ago"
            elsif expiry_days_left == 0
              server_ssl_info[:expiry_info] = "Expiring Today on #{Date.today}"
            else
              server_ssl_info[:expiry_info] = "Expiring in #{expiry_days_left} days"
            end

            if hash_output
              servers_ssl_status.push server_ssl_info
            else
              puts "Server '#{server}:#{server_port}' SSLInfo:"
              puts "   %-25s  :  %s" % ["Name", server_ssl_info[:cn]]
              puts "   %-25s  :  %s" % ["Alternative Name", server_ssl_info[:dns_alt]]
              puts "   %-25s  :  %s" % ["Subject", server_ssl_info[:subject]]
              puts "   %-25s  :  %s" % ["Issuer", server_ssl_info[:issuer]]
              puts "   %-25s  :  %s" % ["Valid Status", server_ssl_info[:valid]]
              puts "   %-25s  :  %s" % ["Expiry Date", server_ssl_info[:expiry_date]]
              puts "   %-25s  :  %s" % ["Expiry Info", server_ssl_info[:expiry_info]]
              puts "   %-25s  :  %s" % ["Expiring Days Left", server_ssl_info[:expiry_days_left]]
              puts "---"
            end
          end
        rescue Exception => error
          if hash_output
            server_ssl_info[:error_conn] = true
            server_ssl_info[:error_message] = "#{error.class}, #{error.message}"
            servers_ssl_status.push server_ssl_info
          else
            puts "Server '#{server}:#{server_port}' SSLInfo:"
            puts "   Caught Exception: #{error.class}, #{error.message}, timeout=#{server_timeout}"
          end
        end
      end
    }
    server_threads.each {|thr| thr.join  }
    return servers_ssl_status if hash_output
  end

end

