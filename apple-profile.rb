#!/usr/bin/ruby

# Apple iOS profile service using Rack
# Copyright Kenley Cheung 2011
# Licensed under the Apache License, Version 2.0.
# See LICENSE file for details.

require 'rubygems'

# Required for generating the actual profiles.
require 'plist'
require 'uuidtools'

class AppleProfile
  def self.general_payload(options)
    payload = Hash.new
    payload['PayloadVersion'] = 1
    payload['PayloadUUID'] = UUIDTools::UUID.random_create().to_s
    payload['PayloadIdentifier'] = options['ProfileIdentifier']   
    
    # Description
    payload['PayloadDisplayName'] = options['ProfileDisplayName']
    # Optional values
    if (options['ProfileDescription'])
      payload['PayloadDescription'] = options['ProfileDescription']
    end
    if (options['Organization'])
      payload['PayloadOrganization'] = options['Organization']
    end
    
    payload
  end
  
  def profile_service_payload(request, challenge, options)
    payload = general_payload(options)
    
    # General settings
    payload['PayloadType'] = "Profile Service"
    
    # URL
    payload_content['URL'] = options['URL']
    # Device attributes - collect all the things by default
    payload_content['DeviceAttributes'] = ["UDID", "VERSION", "PRODUCT", "MAC_ADDRESS_EN0", "DEVICE_NAME", "IMEI", "ICCID"];
    
    # Challenge?
    if (challenge && !challenge.empty?)
      payload_content['Challenge'] = challenge
    end
    
    payload['PayloadContent'] = payload_content
    
    payload
  end
  
  def self.configuration_payload(request, options, content)
    payload = general_payload(options)
    
    # General settings
    payload['PayloadType'] = "Configuration"
    
    # Expiration date
    if (options['ProfileExpiration'])
      payload['PayloadExpirationDate'] = options['ProfileExpiration']
    end
    
    # Include payload content if provided.
    if (content && options['Encrypted'])
      payload['EncryptedPayloadContent'] = StringIO.new(content)
    elsif (content && !content.empty?)
      payload['PayloadContent'] = content
    end
    
    # By default, profiles can be removed.
    if (options['RemovalDisallowed'])
      payload['PayloadRemovalDisallowed'] = true
    end
    
    payload
  end
  
  def removal_password_payload(options, removal_password)
    payload = general_payload(options)
    payload['PayloadType'] = "com.apple.profileRemovalPassword"
    
    payload['RemovalPassword'] = removal_password
    
    payload
  end
  
  def password_policy_payload(options)
    payload = general_payload(options)
    payload['PayloadType'] = "com.apple.mobiledevice.passwordpolicy"
    
    # Allow simple passcode?  Default is yes.
    if (options['allowSimple'])
      payload['allowSimple'] = options['allowSimple']
    end
    # Force PIN?  Default is no.
    if (options['forcePIN'])
      payload['forcePIN'] = options['forcePIN']
    end
    
    payload
  end
  
  def email_payload(options)
    payload = general_payload(options)
    payload['PayloadType'] = "com.apple.mail.managed"
    
    # Email account description (optional)
    if (!options['EmailAccountName'].empty?)
      payload['EmailAccountName'] = options['EmailAccountName']
    end
    if (!options['EmailAccountDescription'].empty?)
      payload['EmailAccountDescription'] = options['EmailAccountDescription']
    end
    
    # Required fields
    if (!options['EmailAddress'].empty?)
      payload['EmailAddress'] = options['EmailAddress']
      else
      nil
    end
    if (options['EmailAccountType'] = "IMAP")
      payload['EmailAccountType'] = "EmailTypeIMAP"
      elsif (options['EmailAccountType'] = "POP")
      payload['EmailAccountType'] = "EmailTypePOP"
      else
      nil
    end
    
    # Incoming mail server configuration
    
    
    # Outgoing mail server configuration
    
    
    payload
  end
  
  def web_clip_payload(options)
    payload = general_payload(options)
    payload['PayloadType'] = "com.apple.webClip.managed"
    
    # Required values
    if (!options['URL'] && !options['URL'])
      payload['URL'] = options['URL']
      payload['Label'] = options['Label']
    else
      nil
    end
    
    # TODO: Web Clip payload icon conversion
    
    
    if (!options['IsRemovable'])
      payload['IsRemovable'] = options['IsRemovable']
    end
    
    payload
  end
  
  def restrictions_payload(options)
    payload = general_payload(options)
    payload['PayloadType'] = "com.apple.applicationaccess"
    
    # TODO: Finish this.
    
    payload
  end
  
  def ldap_payload(options)
    payload = general_payload(options)
    payload['PayloadType'] = "com.apple.ldap.account"
    
    # TODO: Finish this.
    
    payload
  end
  
  def caldav_payload(options)
    payload = general_payload(options)
    payload['PayloadType'] = "com.apple.caldav.account"
    
    # TODO: Finish this.
    
    payload
  end
  
  def calsub_payload(options)
    payload = general_payload(options)
    payload['PayloadType'] = "com.apple.subscribedcalendar.account"
    
    # TODO: Finish this.
    
    payload
  end
  
  def scep_payload(options)
    payload = general_payload(options)
    payload['PayloadType'] = "com.apple.encrypted-profile-service"
    
    # TODO: Finish this.
    
    payload
  end
  
  def apn_payload(options)
    payload = general_payload(options)
    payload['PayloadType'] = "com.apple.apn.managed"
    
    # TODO: Finish this.
    
    payload
  end
  
  def exchange_payload(options)
    payload = general_payload(options)
    payload['PayloadType'] = "com.apple.eas.account"
    
    # TODO: Finish this.
    
    payload
  end
  
  def vpn_payload(options)
    payload = general_payload(options)
    payload['PayloadType'] = "com.apple.vpn.managed"
    
    # TODO: Finish this.
    
    payload
  end
  
  def self.wifi_payload(options)
    payload = general_payload(options)
    payload['PayloadType'] = "com.apple.wifi.managed"
    
    # Required values
    if (options.has_key?("ssid") && options.has_key?("encryption"))
      payload['SSID_STR'] = options['ssid']
      payload['EncryptionType'] = options['encryption']
      if (options["hidden"])
        payload['HIDDEN_NETWORK'] = true
      else
        payload['HIDDEN_NETWORK'] = false
      end
    else
      nil
    end
    
    # Optional values
    if (options.has_key?("password"))
      payload['Password'] = options['password']
    end
    if (options.has_key?("eap_client_configuration"))
      payload['EAPClientConfiguration'] = options['eap_client_configuration']
    end
    
    payload
  end
  
  def eap_client_configuration(options)
    payload = Hash.new
    
    # Required values
    if (options.has_key?("eap_types"))
      payload['AcceptEapTypes'] = options['eap_types']
    else
      nil
    end
    
    # Optional values
    if (options.has_key?("user_name"))
      payload['UserName'] = options['user_name']
    end
    if (options.has_key?("certificate_anchor"))
      payload['PayloadCertificateAnchorUUID'] = options['certificate_anchor']
      # Allow exceptions?
      if (options['allow_trust_execptions'])
        payload['TLSAllowTrustExceptions'] = true
      end
    end
    if (options.has_key?("trusted_server_names"))
      payload['TLSTrustedServerNames'] = options['trusted_server_name']
      # Allow exceptions?
      if (options['allow_trust_execptions'])
        payload['TLSAllowTrustExceptions'] = true
      end
    end
    if (options.has_key?("tls_inner_auth"))
      if (["PAP", "CHAP", "MSCHAP", "MSCHAPv2"].include?(options['tls_inner_auth']))
        payload['TTLSInnerAuthentication'] = options['tls_inner_auth']
      else
        nil
      end
    end
    if (options.has_key?("outer_identity"))
      if (([21, 25, 43] & options['eap_types']).any?)
        payload['TTLSInnerAuthentication'] = options['outer_identity']
      else
        nil
      end
    end
    
    # Only for EAP-FAST
    if (options['eap_types'].include?(43)) # Check for EAP-FAST in accepted EAP types
      if (options.has_key?("eap-fast_use_pac"))
        payload['EAPFASTUsePAC'] = options['eap-fast_use_pac']
      end
      if (payload['EAPFASTUsePAC'] && options.has_key?("eap-fast_provision_pac"))
        payload['EAPFASTProvisionPAC'] = options['eap-fast_provision_pac']
      end
      if (payload['EAPFASTProvisionPAC'] && options.has_key?("eap-fast_provision_pac_anon"))
        payload['EAPFASTProvisionPACAnonymously'] = options['eap-fast_provision_pac_anon']
      end
    end
    
    # Client certificates
    if (options.has_key?("certificate_uuid"))
      payload['PayloadCertificateUUID'] = options['certificate_uuid']
    end
    
    payload
  end
  
  
  # Protect payload generation functions
  #protected :general_payload, :profile_service_payload, :configuration_payload, :removal_password, :password_policy_payload, :email_payload, :web_clip_payload
end
