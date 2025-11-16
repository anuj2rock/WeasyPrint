**The Awesome Document Factory**

WeasyPrint is a smart solution helping web developers to create PDF
documents. It turns simple HTML pages into gorgeous statistical reports,
invoices, tickets…

From a technical point of view, WeasyPrint is a visual rendering engine for
HTML and CSS that can export to PDF. It aims to support web standards for
printing. WeasyPrint is free software made available under a BSD license.

It is based on various libraries but *not* on a full rendering engine like
WebKit or Gecko. The CSS layout engine is written in Python, designed for
pagination, and meant to be easy to hack on.

* Free software: BSD license
* For Python 3.9+, tested on CPython and PyPy
* Documentation: https://doc.courtbouillon.org/weasyprint
* Examples: https://weasyprint.org/#samples
* Changelog: https://github.com/Kozea/WeasyPrint/releases
* Code, issues, tests: https://github.com/Kozea/WeasyPrint
* Code of conduct: https://www.courtbouillon.org/code-of-conduct
* Professional support: https://www.courtbouillon.org
* Donation: https://opencollective.com/courtbouillon

WeasyPrint has been created and developed by Kozea (https://kozea.fr/).
Professional support, maintenance and community management is provided by
CourtBouillon (https://www.courtbouillon.org/).

Copyrights are retained by their contributors, no copyright assignment is
required to contribute to WeasyPrint. Unless explicitly stated otherwise, any
contribution intentionally submitted for inclusion is licensed under the BSD
3-clause license, without any additional terms or conditions. For full
authorship information, see the version control history.


Local HTTP API
--------------

WeasyPrint ships with a small FastAPI service that exposes the PDF renderer
over HTTP. Install the optional dependencies with:

.. code-block:: bash

    pip install "weasyprint[api]"

The application can be served with Python directly:

.. code-block:: bash

    python -m weasyprint.api

or by relying on Uvicorn:

.. code-block:: bash

    uvicorn weasyprint.api:app --reload

The service exposes ``POST /v1/pdf`` and expects JSON containing the HTML
string, optional ``base_url``, stylesheet or attachment descriptors, and
``pdf_options`` matching ``DEFAULT_OPTIONS``. The response includes the PDF as
base64 together with the collected logs:

.. code-block:: bash

    curl -X POST http://127.0.0.1:8000/v1/pdf \
        -H 'Content-Type: application/json' \
        -d '{"html": "<h1>Hello</h1>", "stylesheets": [{"string": "h1 { color: #333; }"}]}'

Or with HTTPie:

.. code-block:: bash

    http POST :8000/v1/pdf html='<h1>Hello</h1>' \
        stylesheets:='[{"string": "h1 { color: #333; }"}]'

The JSON body contains ``pdf`` (base64 PDF), ``progress_log`` with the "Step
1" to "Step 7" messages, ``log`` for general warnings, and ``warnings`` listing
individual warning messages.
