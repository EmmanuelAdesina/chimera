# chimera/knowledge/frameworks/django_security_model.py

from typing import Dict, List, Optional
from pydantic import BaseModel

class FrameworkSecurityModel(BaseModel):
    framework: str
    version_range: str
    input_parsers: Dict[str, str]  # {"request.POST": "multipart_parser", "request.GET": "query_string_parser"}
    default_sanitizers: Dict[str, str]  # {"ORM": "parameterized_queries", "Templates": "auto_escape"}
    known_weaknesses: List[str]  # ["raw() SQL method", "extra() queryset", "mark_safe()"]
    trust_boundaries: List[str]  # ["URL routing -> View", "View -> Template", "Template -> Browser"]
    auth_patterns: Dict[str, str]  # {"default": "session_cookie", "API": "token_auth"}

class DjangoSecurityModel:
    """
    The AI loads this to reason about Django-specific intent:
    'The developer used request.POST directly in a raw SQL string.
     In Django, request.POST is parsed by the multipart parser, then 
     becomes a Python dict. The developer thinks the ORM protects them,
     but raw() bypasses the ORM sanitizer entirely.'
    """
    
    MODEL = FrameworkSecurityModel(
        framework="Django",
        version_range=">=3.0",
        input_parsers={
            "request.POST": "django.http.multipartparser.MultiPartParser",
            "request.GET": "django.http.request.QueryDict",
            "request.body": "raw_bytes",
            "request.headers": "django.http.request.HttpHeaders"
        },
        default_sanitizers={
            "ORM": "django.db.models.query.QuerySet (parameterized)",
            "Templates": "django.template.defaultfilters.escape",
            "Forms": "django.forms.Field.clean"
        },
        known_weaknesses=[
            "Model.objects.raw() accepts format strings",
            "QuerySet.extra() allows SQL injection via where/tables parameters",
            "mark_safe() disables auto-escaping in templates",
            "pickle.loads() on signed cookies before Django 4.0"
        ],
        trust_boundaries=[
            "WAF/Reverse Proxy -> Django URL Router",
            "URL Router -> View Function/Class",
            "View -> ORM/Template/Form",
            "Template -> Browser DOM"
        ],
        auth_patterns={
            "default": "django.contrib.auth.session",
            "API": "django_rest_framework.authentication.TokenAuthentication",
            "OAuth": "django_oauth_toolkit"
        }
    )
    
    @classmethod
    def get_parser_for_source(cls, source_name: str) -> Optional[str]:
        """Map a source variable to its parser implementation."""
        return cls.MODEL.input_parsers.get(source_name)
    
    @classmethod
    def is_known_weakness(cls, code_pattern: str) -> bool:
        """Check if a code pattern matches a known Django anti-pattern."""
        return any(weakness in code_pattern for weakness in cls.MODEL.known_weaknesses)