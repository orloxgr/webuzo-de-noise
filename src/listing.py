"""Shared display sizes; All has no record-count ceiling."""
SIZES = (20, 50, 100, 500, 'all')


def size(value):
    if value == 'all' or type(value) is int and value in SIZES:
        return value
    raise ValueError('Select 20, 50, 100, 500 or All records per page')


def pagination(total, page=1, per_page=20):
    size(per_page)
    if type(page) is not int or page < 1:
        raise ValueError('Invalid list page')
    pages = max(1, (total + per_page - 1) // per_page) if per_page != 'all' else 1
    page = min(page, pages)
    return dict(total=total, page=page, pages=pages, per_page=per_page)


def bounds(meta):
    count = meta['per_page']
    return (-1, 0) if count == 'all' else (count, (meta['page'] - 1) * count)
