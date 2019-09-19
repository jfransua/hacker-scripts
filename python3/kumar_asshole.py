#!/usr/bin/env python3

# Importing required libraries
import pickle
import os.path
import re
import dateutil.parser as parser
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from email.mime.text import MIMEText
from base64 import urlsafe_b64encode

KEYWORDS_REGEX = re.compile(r'Opportunity|Opportunities|Senior Developer', re.IGNORECASE)

REPLY_BODY = "Thanks for sending me information about this opportunity, I look forward to speaking with you soon."

'''
This script does the following:
- Go to Gmal inbox
- Find and read all the unread messages
- Extract details (Date, Sender, Subject, Snippet, Body) and export them to a .csv file / DB
- Mark the messages as Read - so that they are not read again 
'''

'''
Before running this script, the user should get the authentication by following 
the link: https://developers.google.com/gmail/api/quickstart/python
Also, client_secret.json should be saved in the same directory as this file
'''
# https://developers.google.com/gmail/api/guides/sending
def create_message(sender, to, subject, message_text):
  """Create a message for an email.
  Args:
    sender: Email address of the sender.
    to: Email address of the receiver.
    subject: The subject of the email message.
    message_text: The text of the email message.
  Returns:
    An object containing a base64url encoded email object.
  """
  message = MIMEText(message_text)
  message['to'] = to
  message['from'] = sender
  message['subject'] = subject
  encoded_message = urlsafe_b64encode(message.as_bytes())
  return {'raw': encoded_message.decode()}


# https://developers.google.com/gmail/api/guides/sending
def send_message(service, user_id, message):
  """Send an email message.
  Args:
    service: Authorized Gmail API service instance.
    user_id: User's email address. The special value "me"
    can be used to indicate the authenticated user.
    message: Message to be sent.
  Returns:
    Sent Message.
  """
  try:
    message = (service.users().messages().send(userId=user_id, body=message)
               .execute())
    print('Message Id: %s' % message['id'])
    return message
  #except errors.HttpError, error:
  except Exception as error:
    print('An error occurred: %s' % error)


# Creating a storage.JSON file with authentication details
SCOPES = 'https://www.googleapis.com/auth/gmail.modify'  # we are using modify and not readonly, as we will be marking the messages Read
creds = None
# The file token.pickle stores the user's access and refresh tokens, and is
# created automatically when the authorization flow completes for the first
# time.
if os.path.exists('token.pickle'):
    with open('token.pickle', 'rb') as token:
        creds = pickle.load(token)
# If there are no (valid) credentials available, let the user log in.
if not creds or not creds.valid:
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
    else:
        flow = InstalledAppFlow.from_client_secrets_file(
            'credentials.json', SCOPES)
        creds = flow.run_local_server(port=0)
    # Save the credentials for the next run
    with open('token.pickle', 'wb') as token:
        pickle.dump(creds, token)


user_id = 'Jerome.Fransua@gmail.com'
label_id_one = 'INBOX'
label_id_two = 'UNREAD'
service = build('gmail', 'v1', credentials=creds)

# Getting all the unread messages from Inbox
# labelIds can be changed accordingly
unread_msgs = service.users().messages().list(userId=user_id, labelIds=[label_id_one, label_id_two]).execute()

# We get a dictonary. Now reading values for the key 'messages'
mssg_list = []
if 'messages' in unread_msgs:
  mssg_list.extend(unread_msgs['messages'])


print("Total unread messages in inbox: ", str(len(mssg_list)))

final_list = []
msgs_sent = 0

for mssg in mssg_list:
    temp_dict = {}
    m_id = mssg['id']  # get id of individual message
    message = service.users().messages().get(userId=user_id, id=m_id).execute()  # fetch the message using API
    payld = message['payload']  # get payload of the message
    headr = payld['headers']  # get header of the payload
    msg_subject = None
    msg_from = None

    for one in headr:  # getting the Subject
        if one['name'] == 'Subject':
            msg_subject = one['value']
            temp_dict['Subject'] = msg_subject
        else:
            pass

    for two in headr:  # getting the date
        if two['name'] == 'Date':
            msg_date = two['value']
            date_parse = (parser.parse(msg_date))
            m_date = (date_parse.date())
            temp_dict['Date'] = str(m_date)
        else:
            pass

    for three in headr:  # getting the Sender
        if three['name'] == 'From':
            msg_from = three['value']
            temp_dict['Sender'] = msg_from
        else:
            pass

    temp_dict['Snippet'] = message['snippet']  # fetching message snippet

    try:
        # Fetching message body
        if KEYWORDS_REGEX.search(msg_subject):
            # Send a reply.
            #mail.add_label('Database fixes')
            print ('Found match, preparing to send message.')
            raw_msg = create_message(user_id, msg_from, msg_subject, REPLY_BODY)
            send_message(service, user_id, raw_msg)

            # This will mark the message as read
            service.users().messages().modify(userId=user_id, id=m_id, body={'removeLabelIds': ['UNREAD']}).execute()
            msgs_sent += 1
        else:
            print ("Didn't find keywords in Subject: " % msg_subject)

    except Exception as e:
        print ('An error occurred: %s' % e)
        pass

    print(temp_dict)
    final_list.append(temp_dict)  # This will create a dictonary item in the final list

print("Total messages retrived: ", str(len(final_list)))
print("Total messages sent: ", str(msgs_sent))


