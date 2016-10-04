require 'json'
require 'sinatra'
require 'sinatra/json'
require 'openssl'
require 'faraday'

# NOTE: Webhooks must be available via SSL with a certificate signed by a valid
# certificate authority. The easiest way to deploy and test this code is on
# Heroku (http://www.heroku.com)

# Be sure to setup your config values before running this code. You can
# set them using environment variables or modifying the config file in /config.

# App Secret can be retrieved from the App Dashboard
APP_SECRET = ENV['APP_SECRET']

# Arbitrary value used to validate a webhook
VALIDATION_TOKEN = ENV['VALIDATION_TOKEN']

# Generate a page access token for your page from the App Dashboard
PAGE_ACCESS_TOKEN = ENV['PAGE_ACCESS_TOKEN']

# URL where the app is running (include protocol). Used to point to scripts and
# assets located at this address.
SERVER_URL = ENV['SERVER_URL']

%w(APP_SECRET VALIDATION_TOKEN PAGE_ACCESS_TOKEN SERVER_URL).each do |var|
  unless var
    $stderr.puts "Missing config value for #{var}"
    exit 1
  end
end


# Use your own validation token. Check that the token used in the Webhook
# setup is the same token used here.

get '/webhook' do
  if params['hub.mode'] == 'subscribe' && params['hub.verify_token'] == VALIDATION_TOKEN
    puts 'Validating webhook'
    return 200, params['hub.challenge']
  else
    $stderr.puts 'Failed validation. Make sure the validation tokens match.'
    return 403
  end
end


# All callbacks for Messenger are POST-ed. They will be sent to the same
# webhook. Be sure to subscribe your app to your page to receive callbacks
# for your page.
# https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app

post '/webhook' do
  request.body.rewind  # in case someone already read it
  data = JSON.parse request.body.read

  # Make sure this is a page subscription
  if data['object'] == 'page'
    # Iterate over each entry
    # There may be multiple if batched
    data['entry'].each do |pageEntry|
      page_id = pageEntry['id']
      time_of_event = pageEntry['time']
      puts "page_id => #{page_id}"
      puts "time_of_event => #{time_of_event}"

      # Iterate over each messaging event
      pageEntry['messaging'].each do |messagingEvent|
        if messagingEvent['optin']
          received_authentication(messagingEvent)
        elsif messagingEvent['message']
          received_message(messagingEvent)
        elsif messagingEvent['delivery']
          received_delivery_confirmation(messagingEvent)
        elsif messagingEvent['postback']
          received_postback(messagingEvent)
        elsif messagingEvent['read']
          received_message_read(messagingEvent)
        elsif (messagingEvent.account_linking)
          received_account_link(messagingEvent)
        else
          puts "Webhook received unknown messagingEvent: #{messagingEvent}"
        end
      end
    end
  end

  # Assume all went well.
  #
  # You must send back a 200, within 20 seconds, to let us know you've
  # successfully received the callback. Otherwise, the request will time out.
  return 200
end


# This path is used for account linking. The account linking call-to-action
# (sendAccountLinking) is pointed to this URL.

get '/authorize' do
  account_linking_token = params['account_linking_token']
  redirect_uri = params['redirect_uri']

  # Authorization Code should be generated per user by the developer. This will
  # be passed to the Account Linking callback.
  authorization_code = '1234567890'

  # Redirect users to this URI on successful login
  redirectURISuccess = redirect_uri + '&authorization_code=' + authorization_code

  erb 'authorize', locals: {
    accountLinkingToken: account_linking_token,
    redirectURI: redirect_uri,
    redirectURISuccess: redirectURISuccess
  }
end


# Verify that the callback came from Facebook. Using the App Secret from
# the App Dashboard, we can verify the signature that is sent with each
# callback in the x-hub-signature field, located in the header.
#
# https://developers.facebook.com/docs/graph-api/webhooks#setup

before do
  verify_request_signature(request, response)
end

def verify_request_signature(request, response)
  signature = headers['x-hub-signature']
  puts "x-hub-signature: #{signature}"

  if !signature
    # For testing, let's log an error. In production, you should throw an
    # error.
    $stderr.puts "Couldn't validate the signature."
  else
    method, signature_hash  = *signature.split('=')
    unless method == 'sha1'
      $stderr.puts 'Unknown signature method'
      halt 400
    end

    request.body.rewind

    sha1 = OpenSSL::Digest.new('sha1')
    expected_hash = OpensSSL::HMAC.hexdigest(sha1, APP_SECRET, request.body.read)

    unless expected_hash == signature_hash
      $stderr.puts "Couldn't validate the request signature."
      halt 400
    end
  end
end


# Authorization Event
#
# The value for 'optin.ref' is defined in the entry point. For the "Send to
# Messenger" plugin, it is the 'data-ref' field. Read more at
# https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication

def received_authentication(event)
  sender_id = event['sender']['id']
  recipient_id = event['recipient']['id']
  time_of_auth = event['timestamp']

  # The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
  # The developer can set this to an arbitrary value to associate the
  # authentication callback with the 'Send to Messenger' click event. This is
  # a way to do account linking when the user clicks the 'Send to Messenger'
  # plugin.
  passThroughParam = event['optin']['ref']

  puts "Received authentication for user #{sender_id} and page #{recipient_id} with pass through param '#{passThroughParam}' at #{time_of_auth}"

  # When an authentication is received, we'll send a message back to the sender
  # to let them know it was successful.
  send_text_message(sender_id, 'Authentication successful')
end


# Message Event
#
# This event is called when a message is sent to your page. The 'message'
# object format can vary depending on the kind of message that was received.
# Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
#
# For this example, we're going to echo any text that we get. If we get some
# special keywords ('button', 'generic', 'receipt'), then we'll send back
# examples of those bubbles to illustrate the special message bubbles we've
# created. If we receive a message with an attachment (image, video, audio),
# then we'll simply confirm that we've received the attachment.

def received_message(event)
  sender_id = event['sender']['id']
  recipient_id = event['recipient']['id']
  time_of_message = event['timestamp']
  message = event['message']

  puts "Received message for user #{sender_id} and page #{recipient_id} at #{time_of_message} with message: #{message}"
  puts JSON.pretty_generate(message)

  message_id = message['mid']
  puts "message_id => #{message_id}"

  # You may get a text or attachment but not both
  message_text = message['text']
  message_attachments = message['attachments']

  if message_text

    # If we receive a text message, check to see if it matches any special
    # keywords and send back the corresponding example. Otherwise, just echo
    # the text we received.
    case message_text
      when 'image'
        send_image_message(sender_id)
      when 'gif'
        send_gif_message(sender_id)
      when 'audio'
        send_audio_message(sender_id)
      when 'video'
        send_video_message(sender_id)
      when 'file'
        send_file_message(sender_id)
      when 'button'
        send_button_message(sender_id)
      when 'generic'
        send_generic_message(sender_id)
      when 'receipt'
        send_receipt_message(sender_id)
      when'quick reply'
        send_quick_reply(sender_id)
      when 'read receipt'
        send_read_receipt(sender_id)
      when 'typing on'
        send_typing_on(sender_id)
      when 'typing off'
        send_typing_off(sender_id)
      when 'account linking'
        send_account_linking(sender_id)
      else
        send_text_message(sender_id, message_text)
    end
  elsif message_attachments
    send_text_message(sender_id, 'Message with attachment received')
  end
end


# Delivery Confirmation Event
#
# This event is sent to confirm the delivery of a message. Read more about
# these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered

def received_delivery_confirmation(event)
  sender_id = event['sender']['id']
  recipient_id = event['recipient']['id']
  delivery = event['delivery']
  message_ids = delivery['mids']
  watermark = delivery['watermark']
  sequence_number = delivery['seq']

  if (message_ids)
    message_ids.each do |messsage_id|
      puts "Received delivery confirmation for message ID: #{messsage_id} (#{sequence_number}) from #{sender_id} to #{recipient_id}"
    end
  end

  puts "All messages before #{watermark} were delivered."
end


# Postback Event
#
# This event is called when a postback is tapped on a Structured Message.
# https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received

def received_postback(event)
  sender_id = event['sender']['id']
  recipient_id = event['recipient']['id']
  time_of_postback = event['timestamp']

  # The 'payload' param is a developer-defined field which is set in a postback
  # button for Structured Messages.
  payload = event.postback.payload

  puts "Received postback for user #{sender_id} and page #{recipient_id} with payload '#{payload}' at #{time_of_postback}"

  # When a postback is called, we'll send a message back to the sender to
  # let them know it was successful
  send_text_message(sender_id, 'Postback called')
end


# Message Read Event
#
# This event is called when a previously-sent message has been read.
# https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-read

def received_message_read(event)
  sender_id = event['sender']['id']
  recipient_id = event['recipient']['id']

  # All messages before watermark (a timestamp) or sequence have been seen.
  watermark = event['read']['watermark']
  sequence_number = event['read']['seq']

  puts "Received message read event for watermark #{watermark} and sequence number #{sequence_number}"
end


# Account Link Event
#
# This event is called when the Link Account or UnLink Account action has been
# tapped.
# https://developers.facebook.com/docs/messenger-platform/webhook-reference/account-linking

def received_account_link(event)
  sender_id = event['sender']['id']
  recipient_id = event['recipient']['id']

  status = event['account_linking']['status']
  authCode = event['account_linking']['authorization_code']

  puts "Received account link event with for user #{sender_id} with status #{status} and auth code #{authCode}"
end

#
# Send an image using the Send API.
#
def send_image_message(recipient_id)
  message_data = {
    recipient: {
      id: recipient_id
    },
    message: {
      attachment: {
        type: 'image',
        payload: {
          url: SERVER_URL + '/assets/rift.png'
        }
      }
    }
  }

  call_send_api(message_data)
end


# Send a Gif using the Send API.

def send_gif_message(recipient_id)
  message_data = {
    recipient: {
      id: recipient_id
    },
    message: {
      attachment: {
        type: 'image',
        payload: {
          url: SERVER_URL + '/assets/instagram_logo.gif'
        }
      }
    }
  }

  call_send_api(message_data)
end


# Send audio using the Send API.

def send_audio_message(recipient_id)
  message_data = {
    recipient: {
      id: recipient_id
    },
    message: {
      attachment: {
        type: 'audio',
        payload: {
          url: SERVER_URL + '/assets/sample.mp3'
        }
      }
    }
  }

  call_send_api(message_data)
end


# Send a video using the Send API.

def send_video_message(recipient_id)
  message_data = {
    recipient: {
      id: recipient_id
    },
    message: {
      attachment: {
        type: 'video',
        payload: {
          url: SERVER_URL + '/assets/allofus480.mov'
        }
      }
    }
  }

  call_send_api(message_data)
end


# Send a video using the Send API.

def send_file_message(recipient_id)
  message_data = {
    recipient: {
      id: recipient_id
    },
    message: {
      attachment: {
        type: 'file',
        payload: {
          url: SERVER_URL + '/assets/test.txt'
        }
      }
    }
  }

  call_send_api(message_data)
end


# Send a text message using the Send API.

def send_text_message(recipient_id, message_text)
  message_data = {
    recipient: {
      id: recipient_id
    },
    message: {
      text: message_text
    }
  }
  puts "message_data: #{message_data.to_json}"
  call_send_api(message_data)
end


# Send a button message using the Send API.

def send_button_message(recipient_id)
  message_data = {
    recipient: {
      id: recipient_id
    },
    message: {
      attachment: {
        type: 'template',
        payload: {
          template_type: 'button',
          text: 'This is test text',
          buttons:[{
            type: 'web_url',
            url: 'https://www.oculus.com/en-us/rift/',
            title: 'Open Web URL'
          }, {
            type: 'postback',
            title: 'Trigger Postback',
            payload: 'DEVELOPED_DEFINED_PAYLOAD'
          }, {
            type: 'phone_number',
            title: 'Call Phone Number',
            payload: '+16505551234'
          }]
        }
      }
    }
  }

  call_send_api(message_data)
end


# Send a Structured Message (Generic Message type) using the Send API.

def send_generic_message(recipient_id)
  message_data = {
    recipient: {
      id: recipient_id
    },
    message: {
      attachment: {
        type: 'template',
        payload: {
          template_type: 'generic',
          elements: [{
            title: 'rift',
            subtitle: 'Next-generation virtual reality',
            item_url: 'https://www.oculus.com/en-us/rift/',
            image_url: SERVER_URL + '/assets/rift.png',
            buttons: [{
            type: 'web_url',
              url: 'https://www.oculus.com/en-us/rift/',
              title: 'Open Web URL'
            }, {
              type: 'postback',
              title: 'Call Postback',
              payload: 'Payload for first bubble',
            }],
          }, {
            title: 'touch',
            subtitle: 'Your Hands, Now in VR',
            item_url: 'https://www.oculus.com/en-us/touch/',
            image_url: SERVER_URL + '/assets/touch.png',
            buttons: [{
              type: 'web_url',
              url: 'https://www.oculus.com/en-us/touch/',
              title: 'Open Web URL'
            }, {
              type: 'postback',
              title: 'Call Postback',
              payload: 'Payload for second bubble',
            }]
          }]
        }
      }
    }
  }

  call_send_api(message_data)
end


# Send a receipt message using the Send API.

def send_receipt_message(recipient_id)
  # Generate a random receipt ID as the API requires a unique ID
  receipt_id = "order#{rand(1000)}"

  message_data = {
    recipient: {
      id: recipient_id
    },
    message:{
      attachment: {
        type: 'template',
        payload: {
          template_type: 'receipt',
          recipient_name: 'Peter Chang',
          order_number: receipt_id,
          currency: 'USD',
          payment_method: 'Visa 1234',
          timestamp: '1428444852',
          elements: [{
            title: 'Oculus Rift',
            subtitle: 'Includes: headset, sensor, remote',
            quantity: 1,
            price: 599.00,
            currency: 'USD',
            image_url: SERVER_URL + '/assets/riftsq.png'
          }, {
            title: 'Samsung Gear VR',
            subtitle: 'Frost White',
            quantity: 1,
            price: 99.99,
            currency: 'USD',
            image_url: SERVER_URL + '/assets/gearvrsq.png'
          }],
          address: {
            street_1: '1 Hacker Way',
            street_2: '',
            city: 'Menlo Park',
            postal_code: '94025',
            state: 'CA',
            country: 'US'
          },
          summary: {
            subtotal: 698.99,
            shipping_cost: 20.00,
            total_tax: 57.67,
            total_cost: 626.66
          },
          adjustments: [{
            name: 'New Customer Discount',
            amount: -50
          }, {
            name: '$100 Off Coupon',
            amount: -100
          }]
        }
      }
    }
  }

  call_send_api(message_data)
end

#
# Send a message with Quick Reply buttons.
#
#
def send_quick_reply(recipient_id)
  message_data = {
    recipient: {
      id: recipient_id
    },
    message: {
      text: "What's your favorite movie genre?",
      metadata: 'DEVELOPER_DEFINED_METADATA',
      quick_replies: [
        {
          'content_type': 'text',
          'title': 'Action',
          'payload': 'DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_ACTION'
        },
        {
          'content_type': 'text',
          'title': 'Comedy',
          'payload': 'DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_COMEDY'
        },
        {
          'content_type': 'text',
          'title': 'Drama',
          'payload': 'DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_DRAMA'
        }
      ]
    }
  }

  call_send_api(message_data)
end


# Send a read receipt to indicate the message has been read

def send_read_receipt(recipient_id)
  puts 'Sending a read receipt to mark message as seen'

  message_data = {
    recipient: {
      id: recipient_id
    },
    sender_action: 'mark_seen'
  }

  call_send_api(message_data)
end


# Turn typing indicator on

def send_typing_on(recipient_id)
  puts 'Turning typing indicator on'

  message_data = {
    recipient: {
      id: recipient_id
    },
    sender_action: 'typing_on'
  }

  call_send_api(message_data)
end


# Turn typing indicator off

def send_typing_off(recipient_id)
  puts 'Turning typing indicator off'

  message_data = {
    recipient: {
      id: recipient_id
    },
    sender_action: 'typing_off'
  }

  call_send_api(message_data)
end


# Send a message with the account linking call-to-action

def send_account_linking(recipient_id)
  message_data = {
    recipient: {
      id: recipient_id
    },
    message: {
      attachment: {
        type: 'template',
        payload: {
          template_type: 'button',
          text: 'Welcome. Link your account.',
          buttons:[{
            type: 'account_link',
            url: SERVER_URL + '/authorize'
          }]
        }
      }
    }
  }

  call_send_api(message_data)
end


# Call the Send API. The message data goes in the body. If successful, we'll
# get the message id in a response

def call_send_api(message_data)
  client = Faraday.new(url: 'https://graph.facebook.com/v2.6')
  response = client.post do |req|
    req.url '/me/messages', access_token: PAGE_ACCESS_TOKEN
    req.headers['Content-Type'] = 'application/json'
    req.body = message_data.to_json
  end

  if response.status == 200
    body = JSON.parse(response.body)

    recipient_id = body['recipient_id']
    message_id = body['message_id']

    puts "Successfully sent generic message with id #{message_id} to recipient #{recipient_id}"
  else
    $stderr.puts 'Unable to send message.'
    $stderr.puts response.inspect
  end
end

not_found do
  status 404
end
