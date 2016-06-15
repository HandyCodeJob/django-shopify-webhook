Django Shopify Webhook
======================

[![PyPI version](https://badge.fury.io/py/django-shopify-webhook.svg)](http://badge.fury.io/py/django-shopify-webhook)
[![Build Status](https://travis-ci.org/discolabs/django-shopify-webhook.svg?branch=master)](https://travis-ci.org/discolabs/django-shopify-webhook)

This Django package aims to make it easy to add webhook-handling behaviour into
your Django app. It provides:

- A `WebhookView` for catching and verifying webhooks sent from Shopify, and
  triggering the appropriate webhook signal.
  
- `webhook`, `carrier_request` and `app_proxy` view decorators that validate
  these various types of request.
  
- A number of `WebhookSignal`s that can be listened to and handled by your
  application.

- If you are accepting webhooks via ajax, you need to keep cors in mind. Be
  sure to have
  [djagno-cors-headers](https://github.com/ottoyiu/django-cors-headers) Here is
  an example of the config for corsheaders;

  ```python
  CORS_ORIGIN_WHITELIST = (
      '%s.myshopify.com' % SHOP_NAME,
  )

  CORS_ALLOW_HEADERS = (
      'origin',
      'content-type',
      'accept',
      'authorization',
      'x-requested-with',
      'x-csrftoken',
      'x-shopify-topic',
      'x-shopify-shop-domain',
      'x-shopify-hmac-sha256',
      'x-shopify-*-id',
      'user-agent',
      'referer',
  )
  ```

**Note:** This package is no longer actively developed and I'm unable to provide
support for it. I am happy to review and accept pull requests from anyone who's
using it in their own applications.
