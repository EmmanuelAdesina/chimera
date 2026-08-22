"""
Chimera v4 ASI Module: Caido Epistemic Bridge.
Integrates with Caido's local GraphQL API to programmatically intercept, 
modify, and analyze HTTP traffic as an epistemic sensor.
"""
import aiohttp
import json
from .base_plugin import ToolPlugin
from chimera.models import Evidence

class CaidoBridge(ToolPlugin):
    def __init__(self, config: dict):
        super().__init__(config)
        self.api_url = config.get('caido_url', 'http://127.0.0.1:8080/graphql')
        self.session = None

    async def initialize(self):
        self.session = aiohttp.ClientSession()
        # Verify Caido is running and accessible
        try:
            await self._execute_query("query { __typename }")
        except Exception as e:
            raise ConnectionError(f"Failed to connect to Caido at {self.api_url}: {e}")

    async def _execute_query(self, query: str, variables: dict = None) -> dict:
        payload = {'query': query}
        if variables:
            payload['variables'] = variables
            
        async with self.session.post(self.api_url, json=payload) as resp:
            if resp.status == 200:
                return await resp.json()
            raise Exception(f"Caido GraphQL error: {resp.status}")

    async def execute(self, payload: dict) -> Evidence:
        """
        Injects a crafted HTTP request into Caido's active scan pipeline.
        Caido acts as the epistemic sensor, applying its internal rules and 
        returning the mutated traffic and detected anomalies.
        """
        target_url = payload.get('target_url')
        request_data = payload.get('raw_http_request')
        
        # GraphQL mutation to create a new request entry in Caido
        mutation = """
        mutation CreateRequest($input: CreateRequestInput!) {
            createRequest(input: $input) {
                request { id, url }
            }
        }
        """
        
        variables = {
            "input": {
                "url": target_url,
                "raw": request_data,
                "method": "POST"
            }
        }
        
        result = await self._execute_query(mutation, variables)
        request_id = result['data']['createRequest']['request']['id']
        
        # Trigger Caido's active scan on this specific request
        scan_mutation = """
        mutation StartScan($requestId: ID!) {
            startScan(requestId: $requestId) { id }
        }
        """
        await self._execute_query(scan_mutation, {"requestId": request_id})
        
        return Evidence(
            type="CAIDO_TRAFFIC_INJECTED",
            description=f"Injected traffic into Caido and initiated scan. Request ID: {request_id}",
            confidence=1.0,
            raw_data={'caido_request_id': request_id}
        )

    async def cleanup(self):
        if self.session:
            await self.session.close()
