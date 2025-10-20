"""
Crafty Controller API v2 Client
Handles communication with Crafty Controller instances for server management.
"""

import aiohttp
import asyncio
import logging
from typing import Optional, Dict, List, Any
from datetime import datetime
from shared.colors import red
try:
    from bot.bot import debug_print
except ImportError:
    def debug_print(*args, **kwargs):
        pass

logger = logging.getLogger(__name__)

class CraftyAPIError(Exception):
    """Custom exception for Crafty API errors"""
    pass

class CraftyAPIClient:
    """Client for interacting with Crafty Controller API v2"""
    
    def __init__(self, api_url: str, api_token: str):
        """
        Initialize the Crafty API client
        
        Args:
            api_url: Base URL of the Crafty Controller instance
            api_token: API token for authentication
        """
        self.api_url = api_url.rstrip('/')
        self.api_token = api_token
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
        Make a request to the Crafty API
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (without base URL)
            data: Request data for POST/PUT requests
            
        Returns:
            Response data as dictionary
            
        Raises:
            CraftyAPIError: If the request fails
        """
        url = f"{self.api_url}/api/v2/{endpoint.lstrip('/')}"
        debug_print(f"Making {method} request to {url}", level="all")
        
        if not self.session:
            self.session = aiohttp.ClientSession(headers=self.headers)
        
        try:
            async with self.session.request(method, url, json=data) as response:
                response_data = await response.json()
                
                if response.status >= 400:
                    error_msg = response_data.get('message', f'HTTP {response.status}')
                    debug_print(red(f"Crafty API error: {error_msg}", level="all"))
                    raise CraftyAPIError(f"API request failed: {error_msg}")
                
                debug_print(f"Crafty API response: {response_data}", level="all")
                return response_data
                
        except aiohttp.ClientError as e:
            debug_print(red(f"HTTP client error: {str(e)}", level="all"))
            raise CraftyAPIError(f"Network error: {str(e)}")
        except Exception as e:
            debug_print(red(f"Unexpected error: {str(e)}", level="all"))
            raise CraftyAPIError(f"Unexpected error: {str(e)}")
    
    async def test_connection(self) -> bool:
        """
        Test the connection to the Crafty API
        
        Returns:
            True if connection is successful, False otherwise
        """
        try:
            debug_print(f"Testing connection to {self.api_url}", level="all")
            response = await self._make_request('GET', '/servers')
            debug_print(f"Test connection response: {response}", level="all")
            return 'data' in response
        except CraftyAPIError as e:
            debug_print(red(f"Test connection failed: {e}", level="all"))
            return False
        except Exception as e:
            debug_print(red(f"Test connection unexpected error: {e}", level="all"))
            return False
    
    async def test_connection_detailed(self) -> tuple[bool, str]:
        """
        Test the connection to the Crafty API with detailed error information
        
        Returns:
            Tuple of (success, error_message)
        """
        try:
            debug_print(f"Testing detailed connection to {self.api_url}", level="all")
            
            # Test basic connectivity with servers endpoint
            debug_print("Testing /servers endpoint...", level="all")
            response = await self._make_request('GET', '/servers')
            debug_print(f"Detailed connection test response: {response}", level="all")
            
            if 'data' not in response:
                return False, "Invalid API response format - missing 'data' field"
            
            # Test if we can get server list (basic permission test)
            servers = response.get('data', [])
            debug_print(f"Found {len(servers)} servers in Crafty instance", level="all")
            
            # If we get here, the basic connection works
            return True, f"Connection successful - found {len(servers)} server(s)"
            
        except CraftyAPIError as e:
            error_msg = str(e)
            debug_print(red(f"Detailed connection test failed: {error_msg}", level="all"))
            
            # Provide more specific error messages based on the error
            if "401" in error_msg or "Unauthorized" in error_msg:
                return False, "Authentication failed - check your API token"
            elif "403" in error_msg or "Forbidden" in error_msg:
                return False, "Access denied - API token needs SERVER permissions for /servers endpoint. Enable 'Full Access' or ensure SERVER permissions include COMMANDS (10000000)"
            elif "404" in error_msg:
                return False, "API endpoint not found - check your Crafty Controller URL and ensure it includes the correct port"
            elif "Connection" in error_msg or "timeout" in error_msg.lower():
                return False, "Cannot connect to server - check URL and ensure Crafty Controller is running"
            else:
                return False, f"API Error: {error_msg}"
                
        except Exception as e:
            error_msg = str(e)
            debug_print(red(f"Detailed connection test unexpected error: {error_msg}", level="all"))
            
            if "SSL" in error_msg or "certificate" in error_msg.lower():
                return False, "SSL/TLS error - check if URL should use https:// and certificate is valid"
            elif "timeout" in error_msg.lower():
                return False, "Connection timeout - check URL and network connectivity"
            elif "resolve" in error_msg.lower() or "address" in error_msg.lower():
                return False, "Cannot resolve hostname - check the URL"
            else:
                return False, f"Connection error: {error_msg}"
    
    async def get_servers(self) -> List[Dict[str, Any]]:
        """
        Get all servers from the Crafty instance
        
        Returns:
            List of server data dictionaries
        """
        response = await self._make_request('GET', '/servers')
        return response.get('data', [])
    
    async def get_server(self, server_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a specific server
        
        Args:
            server_id: ID of the server
            
        Returns:
            Server data dictionary or None if not found
        """
        try:
            response = await self._make_request('GET', f'/servers/{server_id}')
            return response.get('data')
        except CraftyAPIError:
            return None
    
    async def get_server_status(self, server_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the status of a specific server
        
        Args:
            server_id: ID of the server
            
        Returns:
            Server status data or None if not found
        """
        try:
            debug_print(f"Getting status for server {server_id}", level="all")
            
            # Try the stats endpoint first (this has real-time running status)
            try:
                response = await self._make_request('GET', f'/servers/{server_id}/stats')
                debug_print(f"Server stats response: {response}", level="all")
                status_data = response.get('data', {})
                
                if status_data:
                    # Try different possible field names for running status in stats endpoint
                    is_running = False
                    
                    # Check various possible fields and values
                    running_checks = [
                        status_data.get('running') == True,
                        status_data.get('running') == 'true',
                        status_data.get('running') == 1,
                        status_data.get('is_running') == True,
                        status_data.get('is_running') == 'true',
                        status_data.get('status', '').lower() == 'running',
                        status_data.get('status', '').lower() == 'online',
                        status_data.get('state', '').lower() == 'running',
                        status_data.get('state', '').lower() == 'online',
                        status_data.get('server_running') == True,
                        status_data.get('server_running') == 'true',
                        status_data.get('online') == True,
                        status_data.get('online') == 'true',
                        status_data.get('active') == True,
                        status_data.get('active') == 'true'
                    ]
                    
                    is_running = any(running_checks)
                    
                    debug_print(f"Stats endpoint - all running checks for {server_id}: {running_checks}", level="all")
                    debug_print(f"Stats endpoint - determined running status for {server_id}: {is_running}", level="all")
                    
                    formatted_status = {
                        'running': is_running,
                        'players': (
                            status_data.get('players', 0) or 
                            status_data.get('online', 0) or
                            status_data.get('players_online', 0) or
                            status_data.get('current_players', 0) or
                            0
                        ),
                        'max_players': (
                            status_data.get('max_players', 0) or
                            status_data.get('max', 0) or 
                            status_data.get('player_limit', 0) or
                            0
                        ),
                        'version': (
                            status_data.get('version') or
                            status_data.get('server_version') or
                            status_data.get('minecraft_version')
                        ),
                        'uptime': (
                            status_data.get('uptime') or
                            status_data.get('server_uptime')
                        ),
                        'online_players': (
                            status_data.get('online_players', []) or
                            status_data.get('players', []) or
                            []
                        )
                    }
                    
                    debug_print(f"Status endpoint - formatted status for {server_id}: {formatted_status}", level="all")
                    return formatted_status
                
                return status_data
            except CraftyAPIError as stats_error:
                debug_print(red(f"Stats endpoint failed for {server_id}: {stats_error}, trying server info endpoint", level="all"))
                
                # Fallback to server info endpoint which often includes status
                response = await self._make_request('GET', f'/servers/{server_id}')
                debug_print(f"Server info response: {response}", level="all")
                server_data = response.get('data', {})
                
                # Extract status information from server data
                if server_data:
                    debug_print(f"Raw server data for {server_id}: {server_data}", level="all")
                    
                    # Try different possible field names for running status
                    is_running = False
                    
                    # Check various possible fields and values  
                    running_checks = [
                        server_data.get('running') == True,
                        server_data.get('running') == 'true',
                        server_data.get('running') == 1,
                        server_data.get('is_running') == True,
                        server_data.get('is_running') == 'true',
                        server_data.get('status', '').lower() == 'running',
                        server_data.get('status', '').lower() == 'online',
                        server_data.get('state', '').lower() == 'running', 
                        server_data.get('state', '').lower() == 'online',
                        server_data.get('server_running') == True,
                        server_data.get('server_running') == 'true',
                        server_data.get('online') == True,
                        server_data.get('online') == 'true',
                        server_data.get('active') == True,
                        server_data.get('active') == 'true'
                    ]
                    
                    is_running = any(running_checks)
                    
                    debug_print(f"Server endpoint - all running checks for {server_id}: {running_checks}", level="all")
                    debug_print(f"Determined running status for {server_id}: {is_running}", level="all")
                    
                    # Crafty often includes status info in the server data
                    status_data = {
                        'running': is_running,
                        'players': (
                            server_data.get('online', 0) or 
                            server_data.get('players_online', 0) or
                            server_data.get('current_players', 0) or
                            0
                        ),
                        'max_players': (
                            server_data.get('max', 0) or 
                            server_data.get('max_players', 0) or
                            server_data.get('player_limit', 0) or
                            0
                        ),
                        'version': (
                            server_data.get('version') or
                            server_data.get('server_version') or
                            server_data.get('minecraft_version')
                        ),
                        'uptime': (
                            server_data.get('uptime') or
                            server_data.get('server_uptime')
                        ),
                        'online_players': (
                            server_data.get('players', []) or
                            server_data.get('online_players', []) or
                            []
                        )
                    }
                    
                    debug_print(f"Formatted status data for {server_id}: {status_data}", level="all")
                    return status_data
                else:
                    return None
                    
        except CraftyAPIError as e:
            debug_print(red(f"CraftyAPIError getting server status for {server_id}: {e}", level="all"))
            return None
        except Exception as e:
            debug_print(red(f"Unexpected error getting server status for {server_id}: {e}", level="all"))
            return None
    
    async def start_server(self, server_id: str) -> bool:
        """
        Start a server
        
        Args:
            server_id: ID of the server to start
            
        Returns:
            True if successful, False otherwise
        """
        try:
            debug_print(f"Attempting to start server {server_id}", level="all")
            await self._make_request('POST', f'/servers/{server_id}/action/start_server')
            debug_print(f"Successfully started server {server_id}", level="all")
            return True
        except CraftyAPIError as e:
            debug_print(red(f"Failed to start server {server_id}: {e}", level="all"))
            return False
    
    async def stop_server(self, server_id: str) -> bool:
        """
        Stop a server
        
        Args:
            server_id: ID of the server to stop
            
        Returns:
            True if successful, False otherwise
        """
        try:
            debug_print(f"Attempting to stop server {server_id}", level="all")
            await self._make_request('POST', f'/servers/{server_id}/action/stop_server')
            debug_print(f"Successfully stopped server {server_id}", level="all")
            return True
        except CraftyAPIError as e:
            debug_print(red(f"Failed to stop server {server_id}: {e}", level="all"))
            return False
    
    async def restart_server(self, server_id: str) -> bool:
        """
        Restart a server
        
        Args:
            server_id: ID of the server to restart
            
        Returns:
            True if successful, False otherwise
        """
        try:
            debug_print(f"Attempting to restart server {server_id}", level="all")
            await self._make_request('POST', f'/servers/{server_id}/action/restart_server')
            debug_print(f"Successfully restarted server {server_id}", level="all")
            return True
        except CraftyAPIError as e:
            debug_print(red(f"Failed to restart server {server_id}: {e}", level="all"))
            return False
    
    async def kill_server(self, server_id: str) -> bool:
        """
        Force kill a server
        
        Args:
            server_id: ID of the server to kill
            
        Returns:
            True if successful, False otherwise
        """
        try:
            debug_print(f"Attempting to kill server {server_id}", level="all")
            await self._make_request('POST', f'/servers/{server_id}/action/kill_server')
            debug_print(f"Successfully killed server {server_id}", level="all")
            return True
        except CraftyAPIError as e:
            debug_print(red(f"Failed to kill server {server_id}: {e}", level="all"))
            return False
    
    async def get_player_count(self, server_id: str) -> Optional[int]:
        """
        Get current player count for a server
        
        Args:
            server_id: ID of the server
            
        Returns:
            Number of online players or None if server is offline/error
        """
        try:
            # Try stats endpoint first
            response = await self._make_request('GET', f'/servers/{server_id}/stats')
            debug_print(f"get_player_count stats response: {response}", level="all")
            data = response.get('data', {}) if response else {}
            player_count = None
            
            # Check for 'online' field first (documented API v2 field)
            if isinstance(data.get('online'), int):
                player_count = data['online']
                debug_print(f"Player count from 'online' field: {player_count}", level="all")
            elif isinstance(data.get('players'), int):
                player_count = data['players']
                debug_print(f"Player count from 'players' field: {player_count}", level="all")
            elif isinstance(data.get('online_players'), list):
                player_count = len(data['online_players'])
                debug_print(f"Player count from 'online_players' list length: {player_count}", level="all")
            
            # Check if server is running (documented API v2 field is 'running')
            running = False
            running_checks = [
                data.get('running') == True,
                data.get('running') == 'true',
                data.get('running') == 1,
                data.get('is_running') == True,
                data.get('is_running') == 'true',
                data.get('status', '').lower() == 'running',
                data.get('status', '').lower() == 'online',
                data.get('state', '').lower() == 'running',
                data.get('state', '').lower() == 'online',
                data.get('server_running') == True,
                data.get('server_running') == 'true',
                data.get('active') == True,
                data.get('active') == 'true'
            ]
            running = any(running_checks)
            debug_print(f"Server running status: {running}", level="all")
            
            if running and player_count is not None:
                debug_print(f"Returning player count: {player_count}", level="all")
                return player_count
            
            # If server is not running, return 0 (offline = no players)
            if not running:
                debug_print(f"Server is not running, returning 0 players", level="all")
                return 0
                
            # Fallback to server info endpoint
            debug_print(f"Fallback: trying server info endpoint", level="all")
            response = await self._make_request('GET', f'/servers/{server_id}')
            debug_print(f"get_player_count info response: {response}", level="all")
            info = response.get('data', {}) if response else {}
            if isinstance(info.get('online'), int):
                debug_print(f"Player count from info 'online' field: {info['online']}", level="all")
                return info['online']
            elif isinstance(info.get('players'), int):
                debug_print(f"Player count from info 'players' field: {info['players']}", level="all")
                return info['players']
            elif isinstance(info.get('online_players'), list):
                count = len(info['online_players'])
                debug_print(f"Player count from info 'online_players' list: {count}", level="all")
                return count
            
            debug_print(f"Could not determine player count, returning None", level="all")
            return None
        except Exception as e:
            debug_print(red(f"Error getting player count for {server_id}: {e}", level="all"))
            return None
    
    async def is_server_idle(self, server_id: str, min_idle_minutes: int = 5) -> tuple[bool, int]:
        """
        Check if a server has no players online
        Note: This only returns current player count. Idle time tracking must be done by the caller.
        
        Args:
            server_id: ID of the server
            min_idle_minutes: Minimum idle time in minutes (unused, kept for compatibility)
            
        Returns:
            Tuple of (has_zero_players, current_player_count)
        """
        try:
            player_count = await self.get_player_count(server_id)
            if player_count is None:
                # Server is not running or error occurred
                debug_print(f"Server {server_id} idle check: unable to determine player count", level="all")
                return False, None
            has_zero_players = player_count == 0
            debug_print(f"Server {server_id} has {player_count} players (zero={has_zero_players})", level="all")
            return has_zero_players, player_count
        except Exception as e:
            debug_print(red(f"Error checking if server {server_id} is idle: {e}", level="all"))
            return False, None  # Do not consider idle on error
    
    async def create_server(self, server_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Create a new server
        
        Args:
            server_data: Server configuration data
            
        Returns:
            Created server data or None if failed
        """
        try:
            response = await self._make_request('POST', '/servers', server_data)
            return response.get('data')
        except CraftyAPIError:
            return None
    
    async def delete_server(self, server_id: str) -> bool:
        """
        Delete a server
        
        Args:
            server_id: ID of the server to delete
            
        Returns:
            True if successful, False otherwise
        """
        try:
            await self._make_request('DELETE', f'/servers/{server_id}')
            return True
        except CraftyAPIError:
            return False
    
    async def get_server_logs(self, server_id: str, lines: int = 100) -> Optional[List[str]]:
        """
        Get server logs
        
        Args:
            server_id: ID of the server
            lines: Number of log lines to retrieve
            
        Returns:
            List of log lines or None if failed
        """
        try:
            response = await self._make_request('GET', f'/servers/{server_id}/logs?lines={lines}')
            return response.get('data', {}).get('logs', [])
        except CraftyAPIError:
            return None
    
    async def send_command(self, server_id: str, command: str) -> bool:
        """
        Send a command to a server
        
        Args:
            server_id: ID of the server
            command: Command to send
            
        Returns:
            True if successful, False otherwise
        """
        try:
            await self._make_request('POST', f'/servers/{server_id}/command', {'command': command})
            return True
        except CraftyAPIError:
            return False
    
    async def get_server_stats(self, server_id: str) -> Optional[Dict[str, Any]]:
        """
        Get server statistics
        
        Args:
            server_id: ID of the server
            
        Returns:
            Server statistics or None if failed
        """
        try:
            response = await self._make_request('GET', f'/servers/{server_id}/stats')
            return response.get('data')
        except CraftyAPIError:
            return None
    
    async def get_server_files(self, server_id: str, path: str = '/') -> Optional[List[Dict[str, Any]]]:
        """
        Get server file listing
        
        Args:
            server_id: ID of the server
            path: Path to list files from
            
        Returns:
            List of file information or None if failed
        """
        try:
            response = await self._make_request('GET', f'/servers/{server_id}/files?path={path}')
            return response.get('data', {}).get('files', [])
        except CraftyAPIError:
            return None

class CraftyManager:
    """Manager class for handling multiple Crafty instances"""
    
    def __init__(self, db):
        """
        Initialize the Crafty manager
        
        Args:
            db: Database instance
        """
        self.db = db
    
    async def get_client(self, instance_id: int) -> Optional[CraftyAPIClient]:
        """
        Get a Crafty API client for a specific instance
        
        Args:
            instance_id: ID of the Crafty instance
            
        Returns:
            CraftyAPIClient instance or None if not found
        """
        instance = self.db.get_crafty_instance(instance_id)
        if not instance:
            debug_print(f"Crafty instance {instance_id} not found in database", level="all")
            return None
        
        if not instance.get('enabled'):
            debug_print(f"Crafty instance {instance_id} is disabled", level="all")
            return None
        
        debug_print(f"Creating client for instance {instance_id}: {instance['api_url']}", level="all")
        return CraftyAPIClient(instance['api_url'], instance['api_token'])
    
    async def test_instance_connection(self, instance_id: int) -> bool:
        """
        Test connection to a Crafty instance
        
        Args:
            instance_id: ID of the Crafty instance
            
        Returns:
            True if connection successful, False otherwise
        """
        client = await self.get_client(instance_id)
        if not client:
            return False
        
        async with client:
            return await client.test_connection()
    
    async def test_instance_connection_detailed(self, instance_id: int) -> tuple[bool, str]:
        """
        Test connection to a Crafty instance with detailed error information
        
        Args:
            instance_id: ID of the Crafty instance
            
        Returns:
            Tuple of (success, error_message)
        """
        client = await self.get_client(instance_id)
        if not client:
            return False, "Could not create API client - instance not found or invalid configuration"
        
        async with client:
            return await client.test_connection_detailed()
    
    async def sync_servers(self, instance_id: int) -> bool:
        """
        Sync servers from a Crafty instance to the database
        
        Args:
            instance_id: ID of the Crafty instance
            
        Returns:
            True if sync successful, False otherwise
        """
        success, _ = await self.sync_servers_with_details(instance_id)
        return success
    
    async def sync_servers_with_details(self, instance_id: int) -> tuple:
        """
        Sync servers from a Crafty instance to the database with detailed error messages
        
        Args:
            instance_id: ID of the Crafty instance
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        client = await self.get_client(instance_id)
        if not client:
            return False, "Failed to create API client - check instance configuration"
        
        try:
            async with client:
                # Test connection first
                if not await client.test_connection():
                    return False, "Failed to connect to Crafty Controller - check URL and API token"
                
                servers = await client.get_servers()
                debug_print(f"Retrieved {len(servers)} servers from Crafty instance {instance_id}", level="all")
                
                # Get existing servers from database
                existing_servers = {s['server_id']: s for s in self.db.get_crafty_servers(instance_id)}
                debug_print(f"Found {len(existing_servers)} existing servers in database", level="all")
                
                # Update/create servers
                synced_count = 0
                for server in servers:
                    try:
                        # Handle different field names that Crafty API might use
                        server_id = server.get('server_id') or server.get('id')
                        server_name = server.get('server_name') or server.get('name', f'Server {server_id}')
                        description = server.get('description', '')
                        port = server.get('server_port') or server.get('port')
                        
                        if not server_id:
                            debug_print(f"Server missing ID field: {server}", level="all")
                            continue
                        
                        debug_print(f"Processing server: {server_name} (ID: {server_id}, Port: {port})", level="all")
                        
                        if server_id in existing_servers:
                            # Update existing server
                            db_server_id = existing_servers[server_id]['id']
                            self.db.update_crafty_server(
                                db_server_id, 
                                server_name=server_name, 
                                description=description, 
                                port=port
                            )
                            debug_print(f"Updated server: {server_name} (ID: {server_id})", level="all")
                        else:
                            # Create new server
                            self.db.create_crafty_server(
                                instance_id, 
                                server_id, 
                                server_name, 
                                description, 
                                port
                            )
                            debug_print(f"Created new server: {server_name} (ID: {server_id})", level="all")
                        
                        synced_count += 1
                    except Exception as server_e:
                        debug_print(red(f"Error processing server {server.get('server_name', server.get('name', 'Unknown'))}: {str(server_e)}", level="all"))
                        continue
                
                if synced_count == 0 and len(servers) > 0:
                    return False, f"Failed to sync any of the {len(servers)} servers found"
                
                return True, f"Successfully synced {synced_count} servers"
                
        except Exception as e:
            error_msg = str(e)
            debug_print(red(f"Error syncing servers: {error_msg}", level="all"))
            
            # Provide more specific error messages based on the error type
            if "Network error" in error_msg:
                return False, f"Network connection failed: {error_msg}"
            elif "API request failed" in error_msg:
                return False, f"Crafty API error: {error_msg}"
            elif "json" in error_msg.lower():
                return False, "Invalid response from Crafty Controller - check if the API is working correctly"
            else:
                return False, f"Sync failed: {error_msg}"
    
    async def get_server_for_command(self, guild_id: str, server_name: str) -> Optional[Dict[str, Any]]:
        """
        Get server information for bot commands
        
        Args:
            guild_id: Discord guild ID
            server_name: Name of the server
            
        Returns:
            Server data with instance info or None if not found
        """
        servers = self.db.get_guild_crafty_servers(guild_id)
        
        for server in servers:
            if server['server_name'].lower() == server_name.lower():
                return server
        
        return None
    
    async def perform_server_action(self, guild_id: str, server_name: str, action: str, user_id: str, user_roles: List[str]) -> tuple[bool, str]:
        """
        Perform an action on a server with permission checking
        
        Args:
            guild_id: Discord guild ID
            server_name: Name of the server
            action: Action to perform (start, stop, restart)
            user_id: Discord user ID
            user_roles: List of user's role IDs
            
        Returns:
            Tuple of (success, message)
        """
        # Get server info
        server = await self.get_server_for_command(guild_id, server_name)
        if not server:
            return False, f"Server '{server_name}' not found."
        
        # Map actions to command names
        command_map = {
            'start': 'start_crafty_server',
            'stop': 'stop_crafty_server', 
            'restart': 'restart_crafty_server'
        }
        
        command_name = command_map.get(action)
        if not command_name:
            return False, f"Unknown action: {action}"
        
        # Check command permissions using the unified permission system
        permissions = self.db.get_command_permissions(guild_id, command_name)
        
        # Check if user has permission
        has_permission = False
        
        # Check user permissions
        allowed_users = permissions.get('allow_users', [])
        for user in allowed_users:
            if user.get('id') == user_id:
                has_permission = True
                break
        
        # Check role permissions if user permission not found
        if not has_permission:
            allowed_roles = permissions.get('allow_roles', [])
            for role in allowed_roles:
                if role.get('id') in user_roles:
                    has_permission = True
                    break
        
        if not has_permission:
            return False, f"You don't have permission to {action} this server."
        
        # Perform action
        client = await self.get_client(server['crafty_instance_id'])
        if not client:
            return False, "Failed to connect to Crafty Controller instance."
        
        try:
            async with client:
                if action == 'start':
                    success = await client.start_server(server['server_id'])
                elif action == 'stop':
                    success = await client.stop_server(server['server_id'])
                elif action == 'restart':
                    success = await client.restart_server(server['server_id'])
                else:
                    return False, f"Unknown action: {action}"
                
                if success:
                    return True, f"Server '{server_name}' {action} command sent successfully."
                else:
                    return False, f"Failed to {action} server '{server_name}'."
                    
        except Exception as e:
            debug_print(red(f"Error performing server action: {str(e)}", level="all"))
            return False, f"Error performing action: {str(e)}"
    
    async def get_servers_status(self, guild_id: str) -> Dict[int, Dict[str, Any]]:
        """
        Get status for all servers in a guild
        
        Args:
            guild_id: Discord guild ID
            
        Returns:
            Dictionary mapping server IDs to their status data
        """
        debug_print(f"Getting server statuses for guild {guild_id}", level="all")
        server_statuses = {}
        servers = self.db.get_guild_crafty_servers(guild_id)
        
        if not servers:
            debug_print(f"No servers found for guild {guild_id}", level="all")
            return server_statuses
        
        debug_print(f"Found {len(servers)} servers for guild {guild_id}", level="all")
        
        # Group servers by instance to minimize connections
        instances = {}
        for server in servers:
            instance_id = server['crafty_instance_id']
            if instance_id not in instances:
                instances[instance_id] = []
            instances[instance_id].append(server)
        
        debug_print(f"Servers grouped into {len(instances)} instances", level="all")
        
        # Get status for each instance's servers
        for instance_id, instance_servers in instances.items():
            debug_print(f"Processing instance {instance_id} with {len(instance_servers)} servers", level="all")
            try:
                client = await self.get_client(instance_id)
                if not client:
                    debug_print(red(f"Failed to get client for instance {instance_id}", level="all"))
                    # Mark all servers in this instance as unknown status
                    for server in instance_servers:
                        server_statuses[server['id']] = {'running': None, 'error': 'Connection failed'}
                    continue
                
                # Test connection first
                async with client:
                    connection_test = await client.test_connection()
                    if not connection_test:
                        debug_print(red(f"Connection test failed for instance {instance_id}", level="all"))
                        for server in instance_servers:
                            server_statuses[server['id']] = {'running': None, 'error': 'API connection failed'}
                        continue
                    
                    debug_print(f"Connection test passed for instance {instance_id}", level="all")
                    
                    for server in instance_servers:
                        debug_print(f"Getting status for server {server['id']} (server_id: {server['server_id']})", level="all")
                        try:
                            status = await client.get_server_status(server['server_id'])
                            if status:
                                debug_print(f"Got status for server {server['id']}: {status}", level="all")
                                server_statuses[server['id']] = status
                            else:
                                debug_print(f"No status returned for server {server['id']}", level="all")
                                server_statuses[server['id']] = {'running': None, 'error': 'Status unavailable'}
                        except Exception as e:
                            debug_print(red(f"Error getting status for server {server['id']}: {str(e)}", level="all"))
                            server_statuses[server['id']] = {'running': None, 'error': str(e)}
                            
            except Exception as e:
                debug_print(red(f"Error connecting to instance {instance_id}: {str(e)}", level="all"))
                # Mark all servers in this instance as unknown status
                for server in instance_servers:
                    server_statuses[server['id']] = {'running': None, 'error': 'Instance error'}
        
        debug_print(f"Final server statuses: {server_statuses}", level="all")
        return server_statuses