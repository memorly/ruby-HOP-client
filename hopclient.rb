# cybersource HOP client
#
#  configure HOP settings on a per environment basis in RAILS_ROOT/config/cybersource.yml. 
#
#  load them with:
#      Signature.load_cybersource_config (typically in environment.rb)
#

require 'openssl'
include OpenSSL

module Signature
  
    def Signature.hop_url(mode=nil)
      mode ||= ENV["RAILS_ENV"]
      if mode == 'production'
        "https://orderpage.ic3.com/hop/orderform.jsp"
      else
        "https://orderpagetest.ic3.com/hop/orderform.jsp"
      end
    end
  
    def Signature.load_cybersource_config
      cybersource_configs = YAML::load(ERB.new(IO.read(File.join(RAILS_ROOT,"config","cybersource.yml"))).result)
      environment_config = cybersource_configs[ENV["RAILS_ENV"]]
      if environment_config
        environment_config.each do |k,v|
          self.const_set(k.upcase.to_sym,v)
        end
      end
    end
    
    def Signature.generate_signature(amt, curr)
      timestamp = get_microtime
      data = MERCHANT_ID + amt + curr + timestamp  
      sig =  "<input type='hidden' name='amount' value='#{amt}'> "
        sig += "<input type='hidden' name='currency' value='#{curr}'> "
        sig += "<input type='hidden' name='orderPage_timestamp' value='#{timestamp}'> "
        sig += "<input type='hidden' name='merchantID' value='#{MERCHANT_ID}'> "
        sig += "<input type='hidden' name='orderPage_signaturePublic' value='#{hop_hash(data, PUB_KEY)}'> "
        sig += "<input type='hidden' name='orderPage_version' value='#{ORDERPAGE_VERSION}'> "
        sig += "<input type='hidden' name='orderPage_serialNumber' value='#{ORDERPAGE_SERIAL}'>"
      sig
    end

    def Signature.get_microtime
      t = Time.now
      sprintf("%d%03d", t.to_i, t.usec / 1000)
    end

    def Signature.hop_hash(data, key)
      Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, key, data))
    end

    def Signature.verify_sig(data, sig)
      pub_digest = hop_hash(data, PUB_KEY)
      pub_digest.eql?(sig)
    end
    
end
