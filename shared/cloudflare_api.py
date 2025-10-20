"""
Cloudflare API Client
Handles DNS SRV record management for Minecraft servers.
"""

import aiohttp
import asyncio
import logging
from typing import Optional, Dict, List, Any
from shared.colors import red
try:
    from bot.bot import debug_print
except ImportError:
    def debug_print(*args, **kwargs):
        pass

logger = logging.getLogger(__name__)

class CloudflareAPIError(Exception):
    """Custom exception for Cloudflare API errors"""
    pass

class CloudflareAPIClient:
    """Client for interacting with Cloudflare API"""
    
    def __init__(self, api_token: str, zone_id: str):
        """
        Initialize the Cloudflare API client
        
        Args:
            api_token: Cloudflare API token
            zone_id: Zone ID for the domain
        """
        self.api_token = api_token
        self.zone_id = zone_id
        self.base_url = "https://api.cloudflare.com/client/v4"
        self.headers = {
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json'
        }
        self.session = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(headers=self.headers)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Make a request to the Cloudflare API
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (without base URL)
            data: Request data for POST/PUT requests
            
        Returns:
            Response data as dictionary
            
        Raises:
            CloudflareAPIError: If the request fails
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        debug_print(f"Making {method} request to {url}", level="all")
        
        if not self.session:
            self.session = aiohttp.ClientSession(headers=self.headers)
        
        try:
            async with self.session.request(method, url, json=data) as response:
                response_data = await response.json()
                
                if not response_data.get('success', False):
                    errors = response_data.get('errors', [])
                    error_msg = '; '.join([err.get('message', 'Unknown error') for err in errors])
                    debug_print(red(f"Cloudflare API error: {error_msg}", level="all"))
                    raise CloudflareAPIError(f"API request failed: {error_msg}")
                
                debug_print(f"Cloudflare API response: {response_data}", level="all")
                return response_data
                
        except aiohttp.ClientError as e:
            debug_print(red(f"HTTP client error: {str(e)}", level="all"))
            raise CloudflareAPIError(f"Network error: {str(e)}")
        except Exception as e:
            debug_print(red(f"Unexpected error: {str(e)}", level="all"))
            raise CloudflareAPIError(f"Unexpected error: {str(e)}")
    
    async def test_connection(self) -> bool:
        """
        Test the connection to the Cloudflare API
        
        Returns:
            True if connection is successful, False otherwise
        """
        try:
            response = await self._make_request('GET', f'/zones/{self.zone_id}')
            return response.get('success', False)
        except CloudflareAPIError:
            return False
    
    async def get_zone_info(self) -> Optional[Dict[str, Any]]:
        """
        Get information about the zone
        
        Returns:
            Zone information or None if failed
        """
        try:
            response = await self._make_request('GET', f'/zones/{self.zone_id}')
            return response.get('result')
        except CloudflareAPIError:
            return None
    
    async def list_dns_records(self, record_type: str = 'SRV', name: str = None) -> List[Dict[str, Any]]:
        """
        List DNS records in the zone
        
        Args:
            record_type: Type of DNS record to filter by
            name: Name to filter by
            
        Returns:
            List of DNS records
        """
        try:
            params = {'type': record_type}
            if name:
                params['name'] = name
            
            query_string = '&'.join([f"{k}={v}" for k, v in params.items()])
            endpoint = f'/zones/{self.zone_id}/dns_records?{query_string}'
            
            response = await self._make_request('GET', endpoint)
            return response.get('result', [])
        except CloudflareAPIError:
            return []
    
    async def create_srv_record(self, hostname: str, port: int, target: str = "mc.randomstuff.cc", 
                                priority: int = 0, weight: int = 5) -> Optional[Dict[str, Any]]:
        """
        Create an SRV record for Minecraft
        
        Args:
            hostname: The hostname for the SRV record
            port: The port number for the Minecraft server
            target: The target server (default: mc.randomstuff.cc)
            priority: Priority value (default: 0)
            weight: Weight value (default: 5)
            
        Returns:
            Created record data or None if failed
        """
        try:
            record_name = f"_minecraft._tcp.{hostname}"
            debug_print(f"Creating SRV record with name: {record_name}", level="all")
            
            record_data = {
                'type': 'SRV',
                'name': record_name,
                'data': {
                    'service': '_minecraft',
                    'proto': '_tcp',
                    'name': hostname,
                    'priority': priority,
                    'weight': weight,
                    'port': port,
                    'target': target
                },
                'ttl': 300  # 5 minutes TTL
            }
            
            debug_print(f"SRV record data: {record_data}", level="all")
            response = await self._make_request('POST', f'/zones/{self.zone_id}/dns_records', record_data)
            debug_print(f"Cloudflare API response: {response}", level="all")
            return response.get('result')
            
        except CloudflareAPIError as e:
            debug_print(red(f"Failed to create SRV record: {str(e)}", level="all"))
            return None
        except Exception as e:
            debug_print(red(f"Unexpected error in create_srv_record: {str(e)}", level="all"))
            return None
    
    async def update_srv_record(self, record_id: str, hostname: str, port: int, 
                                target: str = "mc.randomstuff.cc", priority: int = 0, 
                                weight: int = 5) -> Optional[Dict[str, Any]]:
        """
        Update an existing SRV record
        
        Args:
            record_id: Cloudflare record ID
            hostname: The hostname for the SRV record
            port: The port number for the Minecraft server
            target: The target server (default: mc.randomstuff.cc)
            priority: Priority value (default: 0)
            weight: Weight value (default: 5)
            
        Returns:
            Updated record data or None if failed
        """
        try:
            record_name = f"_minecraft._tcp.{hostname}"
            
            record_data = {
                'type': 'SRV',
                'name': record_name,
                'data': {
                    'service': '_minecraft',
                    'proto': '_tcp',
                    'name': hostname,
                    'priority': priority,
                    'weight': weight,
                    'port': port,
                    'target': target
                },
                'ttl': 300  # 5 minutes TTL
            }
            
            response = await self._make_request('PUT', f'/zones/{self.zone_id}/dns_records/{record_id}', record_data)
            return response.get('result')
            
        except CloudflareAPIError as e:
            debug_print(red(f"Failed to update SRV record: {str(e)}", level="all"))
            return None
    
    async def delete_dns_record(self, record_id: str) -> bool:
        """
        Delete a DNS record
        
        Args:
            record_id: Cloudflare record ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            await self._make_request('DELETE', f'/zones/{self.zone_id}/dns_records/{record_id}')
            return True
        except CloudflareAPIError:
            return False
    
    async def get_dns_record(self, record_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific DNS record
        
        Args:
            record_id: Cloudflare record ID
            
        Returns:
            Record data or None if not found
        """
        try:
            response = await self._make_request('GET', f'/zones/{self.zone_id}/dns_records/{record_id}')
            return response.get('result')
        except CloudflareAPIError:
            return None

class CloudflareManager:
    """Manager class for handling Cloudflare DNS operations"""
    
    def __init__(self, db):
        """
        Initialize the Cloudflare manager
        
        Args:
            db: Database instance
        """
        self.db = db
    
    async def get_client(self, guild_id: str) -> Optional[CloudflareAPIClient]:
        """
        Get a Cloudflare API client for a guild
        
        Args:
            guild_id: Discord guild ID
            
        Returns:
            CloudflareAPIClient instance or None if not configured
        """
        debug_print(f"Getting Cloudflare client for guild {guild_id}", level="all")
        config = self.db.get_cloudflare_config(guild_id)
        debug_print(f"Cloudflare config for guild {guild_id}: {config}", level="all")
        
        if not config:
            debug_print(f"No Cloudflare config found for guild {guild_id}", level="all")
            return None
            
        if not config.get('enabled'):
            debug_print(f"Cloudflare is disabled for guild {guild_id}", level="all")
            return None

        if not config.get('api_token') or not config.get('zone_id'):
            debug_print(f"Cloudflare config incomplete for guild {guild_id}: api_token={bool(config.get('api_token'))}, zone_id={bool(config.get('zone_id'))}", level="all")
            return None
        
        debug_print(f"Creating Cloudflare client for guild {guild_id}", level="all")
        return CloudflareAPIClient(config['api_token'], config['zone_id'])
    
    async def test_guild_connection(self, guild_id: str) -> bool:
        """
        Test Cloudflare connection for a guild
        
        Args:
            guild_id: Discord guild ID
            
        Returns:
            True if connection successful, False otherwise
        """
        client = await self.get_client(guild_id)
        if not client:
            return False
        
        async with client:
            return await client.test_connection()
    
    async def create_minecraft_srv_record(self, guild_id: str, crafty_server_id: int, 
                                          hostname: str, port: int) -> tuple[bool, str]:
        """
        Create a Minecraft SRV record
        
        Args:
            guild_id: Discord guild ID
            crafty_server_id: ID of the Crafty server
            hostname: Hostname for the SRV record
            port: Port number
            
        Returns:
            Tuple of (success, message/record_id)
        """
        debug_print(f"Creating DNS record for guild {guild_id}, server {crafty_server_id}, hostname {hostname}, port {port}", level="all")
        
        client = await self.get_client(guild_id)
        if not client:
            debug_print("Cloudflare not configured for this server", level="all")
            return False, "Cloudflare not configured for this server."
        
        try:
            async with client:
                debug_print(f"Checking for existing records for hostname: {hostname}", level="all")
                # Check if record already exists
                existing_records = await client.list_dns_records('SRV', f"_minecraft._tcp.{hostname}")
                if existing_records:
                    debug_print(f"SRV record already exists for {hostname}", level="all")
                    return False, f"SRV record for '{hostname}' already exists."
                
                debug_print(f"Creating SRV record for hostname: {hostname}, port: {port}", level="all")
                # Create the record
                record = await client.create_srv_record(hostname, port)
                if not record:
                    debug_print(red("Failed to create SRV record - no record returned", level="all"))
                    return False, "Failed to create SRV record."
                
                debug_print(f"SRV record created successfully, record ID: {record['id']}", level="all")
                # Save to database
                self.db.create_minecraft_dns_record(
                    guild_id, 
                    crafty_server_id, 
                    hostname, 
                    port, 
                    record['id']
                )
                
                debug_print(f"DNS record saved to database successfully", level="all")
                return True, record['id']
                
        except Exception as e:
            debug_print(red(f"Error creating SRV record: {str(e)}", level="all"))
            import traceback
            debug_print(f"Traceback: {traceback.format_exc()}", level="all")
            return False, f"Error: {str(e)}"
    
    async def update_minecraft_srv_record(self, guild_id: str, record_id: int, 
                                          hostname: str = None, port: int = None,
                                          priority: int = None, weight: int = None) -> tuple[bool, str]:
        """
        Update a Minecraft SRV record
        
        Args:
            guild_id: Discord guild ID
            record_id: Database record ID
            hostname: New hostname (optional)
            port: New port (optional)
            priority: New priority (optional)
            weight: New weight (optional)
            
        Returns:
            Tuple of (success, message)
        """
        client = await self.get_client(guild_id)
        if not client:
            return False, "Cloudflare not configured for this server."
        
        # Get current record from database
        db_record = self.db.get_minecraft_dns_record(record_id)
        if not db_record:
            return False, "DNS record not found."
        
        new_hostname = hostname or db_record['hostname']
        new_port = port or db_record['port']
        new_priority = priority if priority is not None else db_record.get('priority', 0)
        new_weight = weight if weight is not None else db_record.get('weight', 5)
        
        try:
            async with client:
                # Update Cloudflare record
                updated_record = await client.update_srv_record(
                    db_record['record_id'], 
                    new_hostname, 
                    new_port,
                    priority=new_priority,
                    weight=new_weight
                )
                
                if not updated_record:
                    return False, "Failed to update SRV record."
                
                # Update database
                self.db.update_minecraft_dns_record(
                    record_id, 
                    hostname=new_hostname, 
                    port=new_port,
                    priority=new_priority,
                    weight=new_weight
                )
                
                return True, "SRV record updated successfully."
                
        except Exception as e:
            debug_print(red(f"Error updating SRV record: {str(e)}", level="all"))
            return False, f"Error: {str(e)}"
    
    async def delete_minecraft_srv_record(self, guild_id: str, record_id: int) -> tuple[bool, str]:
        """
        Delete a Minecraft SRV record
        
        Args:
            guild_id: Discord guild ID
            record_id: Database record ID
            
        Returns:
            Tuple of (success, message)
        """
        client = await self.get_client(guild_id)
        if not client:
            return False, "Cloudflare not configured for this server."
        
        # Get current record from database
        db_record = self.db.get_minecraft_dns_record(record_id)
        if not db_record:
            return False, "DNS record not found."
        
        try:
            async with client:
                # Delete from Cloudflare
                success = await client.delete_dns_record(db_record['record_id'])
                
                if not success:
                    return False, "Failed to delete SRV record from Cloudflare."
                
                # Delete from database
                self.db.delete_minecraft_dns_record(record_id)
                
                return True, "SRV record deleted successfully."
                
        except Exception as e:
            debug_print(red(f"Error deleting SRV record: {str(e)}", level="all"))
            return False, f"Error: {str(e)}"
    
    async def sync_dns_records(self, guild_id: str) -> tuple[bool, str]:
        """
        Sync DNS records between Cloudflare and database
        
        Args:
            guild_id: Discord guild ID
            
        Returns:
            Tuple of (success, message)
        """
        client = await self.get_client(guild_id)
        if not client:
            return False, "Cloudflare not configured for this server."
        
        try:
            async with client:
                # Get all SRV records from Cloudflare
                cf_records = await client.list_dns_records('SRV')
                minecraft_records = [r for r in cf_records if r['name'].startswith('_minecraft._tcp.')]
                
                # Get all records from database
                db_records = self.db.get_minecraft_dns_records(guild_id)
                db_record_ids = {r['record_id']: r for r in db_records}
                
                synced = 0
                removed = 0
                
                # Check for orphaned database records
                for db_record in db_records:
                    cf_record_exists = any(cf['id'] == db_record['record_id'] for cf in minecraft_records)
                    if not cf_record_exists:
                        self.db.delete_minecraft_dns_record(db_record['id'])
                        removed += 1
                
                # Update existing records
                for cf_record in minecraft_records:
                    if cf_record['id'] in db_record_ids:
                        # Parse hostname from record name
                        record_name = cf_record['name']
                        if record_name.startswith('_minecraft._tcp.'):
                            hostname = record_name[16:]  # Remove "_minecraft._tcp." prefix
                            port = cf_record['data']['port']
                            
                            db_record = db_record_ids[cf_record['id']]
                            if db_record['hostname'] != hostname or db_record['port'] != port:
                                self.db.update_minecraft_dns_record(
                                    db_record['id'], 
                                    hostname=hostname, 
                                    port=port
                                )
                                synced += 1
                
                return True, f"Sync completed. {synced} records updated, {removed} orphaned records removed."
                
        except Exception as e:
            debug_print(red(f"Error syncing DNS records: {str(e)}", level="all"))
            return False, f"Error: {str(e)}"