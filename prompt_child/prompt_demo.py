import boto3, json

# Create the session
bedrock = boto3.Session(profile_name='add username')

# Create the bedrock-runtime client
bedrock_runtime = bedrock.client(
    service_name='bedrock-runtime',
)

response = bedrock_runtime.invoke_model(
    modelId="add arn here",
    body=json.dumps({
        "promptVariables": {
            "language": {"text": "Python"},
            "code_snippet": {"text": """def hello_world():
    '''
    A simple function that prints a greeting message
    '''
    print('Hello, World!')"""},
            "format": {"text": "markdown"}
        }
    }),
    contentType="application/json",
    accept="application/json"
)

from pprint import pprint

response_body = json.loads(response.get('body').read())
pprint(response_body)
#changes for the sync to bedrock
