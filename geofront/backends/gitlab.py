""":mod:`geofront.backends.gitlab` --- Gitlab organization and key store
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""
import collections
import collections.abc
import json
import logging
import typing
import urllib.request

from paramiko.pkey import PKey
from tsukkomi.typed import typechecked
from werkzeug.http import parse_options_header

from ..identity import Identity
from ..keystore import (DuplicatePublicKeyError, KeyStore,
                        format_openssh_pubkey, get_key_fingerprint,
                        parse_openssh_pubkey)
from .oauth import OAuth2Team, request


__all__ = 'GitlabKeyStore', 'GitLabTeam'


class GitLabTeam(OAuth2Team):
    """Authenticate team membership through Gitlab, and authorize to
    access Gitlab key store.

    :param server_url: the base url of the gitlab server
    :type server_url: :class:`str`
    :param client_id: gitlab api client id
    :type client_id: :class:`str`
    :param client_secret: gitlab api client secret
    :type client_secret: :class:`str`

    """

    _AUTHORIZE_URL = '{0.server_url}/oauth/authorize'
    _ACCESS_TOKEN_URL = '{0.server_url}/oauth/token'
    _USER_URL = '{0.server_url}/api/v3/user'
    _GROUP_URL = '{0.server_url}/api/v3/groups'

    authorize_scope = ''

    allow_callback_url_params = False

    @typechecked
    def __init__(self,
                 server_url: str,
                 client_id: str,
                 client_secret: str) -> None:
        super().__init__(client_id, client_secret)
        self.server_url = server_url
        self.authorize_url = self._AUTHORIZE_URL.format(self)
        self.access_token_url = self._ACCESS_TOKEN_URL.format(self)
        self.user_url = self._USER_URL.format(self)
        self.group_url = self._GROUP_URL.format(self)

    def determine_identity(self, access_token: str) -> Identity:
        user_data = request(access_token, self.user_url)
        return Identity(type(self), user_data['username'], access_token)

    def authorize(self, identity: Identity) -> bool:
        return issubclass(identity.team_type, type(self))

    def list_groups(self, identity: Identity):
        if not issubclass(identity.team_type, type(self)):
            return frozenset()
        try:
            response = request(identity, self.group_url)
        except IOError:
            return frozenset()
        if isinstance(response, collections.abc.Mapping) and \
           'error' in response:
            return frozenset()
        return frozenset(g['name'] for g in response)


class GitlabKeyStore(KeyStore):
    """Use Gitlab account's public keys as key store."""

    LIST_URL = '{0.server_url}/user/keys'
    DEREGISTER_URL = LIST_URL + '/{id}'

    logger = logging.getLogger(__name__ + '.GitlabKeyStore')

    @typechecked
    def __init__(self, team: GitLabTeam) -> None:
        self.team = team

    @typechecked
    def register(self, identity: Identity, public_key: PKey) -> None:
        logger = self.logger.getChild('register')
        title = get_key_fingerprint(public_key)
        data = json.dumps({
            'title': title,
            'key': format_openssh_pubkey(public_key)
        })
        try:
            request(identity, self.LIST_URL.format(self.team), 'POST', data=data.encode())
        except urllib.request.HTTPError as e:
            if e.code != 422:
                raise
            content_type = e.headers.get('Content-Type')
            mimetype, options = parse_options_header(content_type)
            if mimetype != 'application/json':
                raise
            charset = options.get('charset', 'utf-8')
            content_body = e.read().decode(charset)
            logger.debug('response body:\n%s', content_body)
            response = json.loads(content_body)
            for error in response.get('errors', []):
                if not isinstance(error, dict):
                    continue
                elif error.get('field') != 'key':
                    continue
                message = error.get('message', '').strip().lower()
                if message != 'key is already in use':
                    continue
                raise DuplicatePublicKeyError(message)
            raise

    @typechecked
    def _list_keys(self, identity: Identity) -> typing.Iterable[PKey]:
        logger = self.logger.getChild('list_keys')
        keys = request(identity, self.LIST_URL.format(self.team))
        for key in keys:
            try:
                yield parse_openssh_pubkey(key['key']), key
            except Exception as e:
                logger.exception(e)
                continue

    @typechecked
    def list_keys(self, identity: Identity) -> typing.AbstractSet[PKey]:
        return frozenset(pkey for pkey, _ in self._list_keys(identity))

    @typechecked
    def deregister(self, identity: Identity, public_key: PKey) -> None:
        for pkey, key in self._list_keys(identity):
            if pkey == public_key:
                request(identity, self.DEREGISTER_URL.format(self.team, **key), 'DELETE')
                break
