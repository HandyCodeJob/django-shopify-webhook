import json
from functools import wraps

from django.http import HttpResponseBadRequest, HttpResponseForbidden, HttpResponse
from django.conf import settings

from .helpers import domain_is_valid, hmac_is_valid, proxy_signature_is_valid
import logging
log = logging.getLogger(__name__)


class HttpResponseMethodNotAllowed(HttpResponse):
    status_code = 405


def webhook(f):
    """
    A view decorator that checks and validates a Shopify Webhook request.
    """

    @wraps(f)
    def wrapper(request, *args, **kwargs):
        # Ensure the request is a POST request.
        if request.method == 'OPTIONS':
            response = HttpResponse()
            response['CONTENT_TYPE'] = 'application/x-www-form-urlencoded'
            response['Access-Control-Allow-Origin'] = '*'
            response['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
            response['Access-Control-Max-Age'] = 1000
            # note that '*' is not valid for Access-Control-Allow-Headers
            response['Access-Control-Allow-Headers'] = (
                'origin, content-type, accept, x-shopify-topic, '
                'x-shopify-shop-domain, x-shopify-hmac-sha256, '
                'x-shopify-*-id, user-agent, referer')
            return response
        elif request.method != 'POST':
            log.debug("Bad method %s" % request.method)
            return HttpResponseMethodNotAllowed()

        # Try to get required headers and decode the body of the request.
        topic = request.META.get('HTTP_X_SHOPIFY_TOPIC', None)
        domain = request.META.get('HTTP_X_SHOPIFY_SHOP_DOMAIN', None)
        hmac = request.META.get('HTTP_X_SHOPIFY_HMAC_SHA256', None)

        # Check the headers
        if not topic:
            return HttpResponseBadRequest('No topic header')
        if not domain:
            return HttpResponseBadRequest('No domain header')
        try:
            data = json.loads(request.body.decode('utf-8'))
        except ValueError as e:
            log.debug("Bad json %s" % e)
            return HttpResponseBadRequest("Bad json")

        # Verify the domain.
        if not domain_is_valid(domain):
            return HttpResponseBadRequest("Bad domain header")

        # Verify the HMAC.
        if not hmac_is_valid(request.body,
                             settings.SHOPIFY_APP_API_SECRET,
                             hmac):
            log.debug("Bad HMAC")
            return HttpResponseForbidden("Bad HMAC header")

        # Otherwise, set properties on the request object and return.
        request.webhook_topic = topic
        request.webhook_data = data
        request.webhook_domain = domain
        return f(request, *args, **kwargs)

    return wrapper


def carrier_request(f):
    """
    A view decorator that checks and validates a CarrierService request from Shopify.
    """

    @wraps(f)
    def wrapper(request, *args, **kwargs):
        # Ensure the request is a POST request.
        if request.method != 'POST':
            return HttpResponseMethodNotAllowed()

        # Try to get required headers and decode the body of the request.
        try:
            domain  = request.META['HTTP_X_SHOPIFY_SHOP_DOMAIN']
            hmac    = request.META['HTTP_X_SHOPIFY_HMAC_SHA256'] if 'HTTP_X_SHOPIFY_HMAC_SHA256' in request.META else None
            data    = json.loads(request.body)
        except (KeyError, ValueError) as e:
            return HttpResponseBadRequest()

        # Verify the domain.
        if not domain_is_valid(domain):
            return HttpResponseBadRequest()

        # Verify the HMAC.
        if not hmac_is_valid(request.body, settings.SHOPIFY_APP_API_SECRET, hmac):
            return HttpResponseForbidden()

        # Otherwise, set properties on the request object and return.
        request.carrier_request_data    = data
        request.carrier_request_domain  = domain
        return f(request, *args, **kwargs)

    return wrapper


def app_proxy(f):
    """
    A view decorator that checks and validates a Shopify Application proxy request.
    """

    @wraps(f)
    def wrapper(request, *args, **kwargs):

        # Verify the signature.
        if not proxy_signature_is_valid(request, settings.SHOPIFY_APP_API_SECRET):
            return HttpResponseBadRequest()

        return f(request, *args, **kwargs)

    return wrapper
