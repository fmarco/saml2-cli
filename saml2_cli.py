# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import argparse
import base64
import requests
import zlib

from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode


BINDING_HTTP_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
BINDING_HTTP_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
SIG_RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
DIGEST_SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256'



def deflate_and_base64_encode(msg):
    if not isinstance(msg, bytes):
        msg = msg.encode('utf-8')
    return base64.b64encode(zlib.compress(msg)[2:-4])


BINDINGS_TO_SAML2BINDINGS = {
    'redirect':  (BINDING_HTTP_REDIRECT, 'get', deflate_and_base64_encode),
    'post': (BINDING_HTTP_POST, 'post', base64.b64encode)
}


def load_pkey_from_file(path):
    with open(path, 'rb') as fp:
        return RSA.importKey(fp.read())


def make_request(binding, message, destination, key):
    _binding, method, encoding = BINDINGS_TO_SAML2BINDINGS.get(binding)
    print('BINDING: {}'.format(binding))
    print('METHOD: {}'.format(binding))
    print('DESTINATION: {}'.format(destination))
    with open(message, 'rb') as fp:
        message = fp.read()
    encoded_message = encoding(message)
    print('ENCODED MESSAGE: {}'.format(encoded_message))
    if _binding == BINDING_HTTP_REDIRECT:
        arguments = {
            'SAMLRequest': encoded_message,
            'SigAlg': SIG_RSA_SHA256
        }
        args_list = [urlencode({k: arguments[k]}) for k in arguments]
        query_string = '&'.join(args_list).encode('ascii')
        digest = SHA256.new()
        digest.update(query_string)
        private_key = load_pkey_from_file(key)
        signer = PKCS1_v1_5.new(private_key)
        signed = signer.sign(digest)
        arguments['Signature'] = base64.b64encode(signed)
        query_string = urlencode(arguments)
        url = '{}?{}'.format(destination, query_string)
        print('URL: {}'.format(url))
        req_args = [url]
    elif _binding == BINDING_HTTP_POST:
        url = destination
        print('URL: {}'.format(url))
        extra = {'SAMLRequest': encoded_message}
        req_args = [url, extra]
    response = getattr(requests, method)(*req_args, verify=False)
    print('RESPONSE: {}'. format(response.text))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--binding', dest='binding', help='SAML2 binding',
        default='redirect'
    )
    parser.add_argument(
        '--dest', dest='destination',
        help='Idp url'
    )
    parser.add_argument(
        '--msg', dest='msg',
        help='SAML2 request'
    )
    parser.add_argument(
        '--type', dest='msg',
        help='SAML2 request'
    )
    parser.add_argument(
        '--key', dest='key',
        help='Path to the private key'
    )
    args = parser.parse_args()
    make_request(args.binding, args.msg, args.destination, args.key)

