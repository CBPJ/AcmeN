import email.utils
import time


def parse_retry_after(retry_after: str, default_delay=5) -> int:
    """
    Parse the 'Retry-After' header value.

    This function takes the 'Retry-After' header value as input, which can be either an integer or a date string,
    and returns the delay time in seconds. If the input is None, it returns a default delay time.

    See RFC8555 Section 6.6(Rate Limits), RFC7231 Section 7.1.3(Retry-After), RFC7231 Section 7.1.1.1(Date/Time Formats)

    :param retry_after: The 'Retry-After' header value, can be either an integer or a date string.
    :param default_delay: The default delay time in seconds when 'Retry-After' is None.
    :raises ValueError: If the input is not an integer or a date string.
    :return: The delay time in seconds.
    """
    if retry_after is None:
        return default_delay

    if not (isinstance(retry_after, str) or isinstance(retry_after, int)):
        raise ValueError("retry_after should be either string or int")

    if isinstance(retry_after, int) or retry_after.isdigit():
        return int(retry_after)
    else:
        return max(0, int(email.utils.parsedate_to_datetime(retry_after).timestamp() - time.time()))
