#!/usr/bin/env python3
import json
import sys

from urllib import parse, request
from surge2clash import surge_to_clash

InvalidReqRespose = {
    'statusCode': 400,
    'headers': {
        'Content-Type': 'text/plain'
    },
    'body': 'Invalid Request'
}


def lambda_handler(event, context):
    query = parse.parse_qs(event['rawQueryString'])
    if 'url' not in query:
        return InvalidReqRespose
    url = query['url'][0]
    with request.urlopen(url) as f:
        body = f.read().decode()
    clash_config = surge_to_clash(body)
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'text/yaml; charset=utf-8'
        },
        'body': clash_config
    }


def main():
    print(lambda_handler(json.load(sys.stdin), None))


if __name__ == "__main__":
    main()
