# saml2-cli

To install:

`pip install -r requirements.txt`

Arguments:
~~~~
--binding BINDING   SAML2 binding
--dest DESTINATION  Idp url
--msg MSG           SAML2 request
--type MSG          SAML2 request
--key KEY           Path to the private key
~~~~

To run:

`python saml2_cli.py --dest 'some.url' --msg ./path/to/request.xml --key './path/to/privatekey'`
