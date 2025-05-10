# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals
from functools import wraps
import re
import json
import tempfile
import logging
from http import HTTPStatus
from urllib.parse import quote, unquote, urlparse, urljoin, urlencode
import aiohttp

from .constants import BASE_URI, SEARCH_BASE_URI
from .auth import Auth
from .exceptions import ImdbAPIError

logger = logging.getLogger(__name__)


ENDPOINTS = {
    'get_name': '/name/{imdb_id}/fulldetails',
    'get_name_filmography': '/name/{imdb_id}/filmography',
    'get_name_images': '/name/{imdb_id}/images',
    'get_name_videos': '/name/{imdb_id}/videos',
    'get_title_credits': '/title/{imdb_id}/fullcredits',
    'get_title_quotes': '/title/{imdb_id}/quotes',
    'get_title_ratings': '/title/{imdb_id}/ratings',
    'get_title_genres': '/title/{imdb_id}/genres',
    'get_title_similarities': '/title/{imdb_id}/similarities',
    'get_title_awards': '/title/{imdb_id}/awards',
    'get_title_connections': '/title/{imdb_id}/connections',
    'get_title_releases': '/title/{imdb_id}/releases',
    'get_title_versions': '/title/{imdb_id}/versions',
    'get_title_plot': '/title/{imdb_id}/plot',
    'get_title_plot_synopsis': '/title/{imdb_id}/plotsynopsis',
    'get_title_images': '/title/{imdb_id}/images',
    'get_title_videos': '/title/{imdb_id}/videos',
    'get_title_user_reviews': '/title/{imdb_id}/userreviews',
    'get_title_metacritic_reviews': '/title/{imdb_id}/metacritic',
    'get_title_companies': '/title/{imdb_id}/companies',
    'get_title_technical': '/title/{imdb_id}/technical',
    'get_title_trivia': '/title/{imdb_id}/trivia',
    'get_title_goofs': '/title/{imdb_id}/goofs',
    'get_title_soundtracks': '/title/{imdb_id}/soundtracks',
    'get_title_news': '/title/{imdb_id}/news',
    'get_title_plot_taglines': '/title/{imdb_id}/taglines',
}


def logit(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        argstr = ', '.join([str(a) for a in args] +
                           ['{k}={v}' for k, v in kwargs.items()])
        logger.info(f'{fn.__name__}({argstr})')
        return fn(*args, **kwargs)
    return wrapper


class Imdb(Auth):
    def __init__(self, locale=None, exclude_episodes=False, session=None):
        self.locale = locale or 'en_US'
        self.exclude_episodes = exclude_episodes
        self.session = session or aiohttp.ClientSession()
        self._cachedir = tempfile.gettempdir()

    async def __aenter__(self):
        return self

    async def __aexit__(self, etype, evalue, etb):
        if self.session is not None:
            await self.session.close()

    def __getattr__(self, name):
        if name not in ENDPOINTS:
            return super().__getattr__(name)

        uri = ENDPOINTS[name]
        return lambda *args, **kwargs: self._fetch(name, uri, *args, **kwargs)

    @logit
    async def get_title(self, imdb_id):
        self.validate_imdb_id(imdb_id)
        await self._redirection_title_check(imdb_id)
        try:
            resource = await self._get_resource(f'/title/{imdb_id}/auxiliary')
        except LookupError:
            self._title_not_found()

        if (
            self.exclude_episodes is True and
            resource['base']['titleType'] == 'tvEpisode'
        ):
            raise LookupError(
                'Title not found. Title was an episode and '
                '"exclude_episodes" is set to true'
            )
        return resource

    async def title_exists(self, imdb_id):
        self.validate_imdb_id(imdb_id)
        page_url = f'https://www.imdb.com/title/{imdb_id}/'

        async with self.session.head(page_url) as response:
            if response.status == HTTPStatus.OK:
                return True
            elif response.status == HTTPStatus.NOT_FOUND:
                return False
            elif response.status == HTTPStatus.MOVED_PERMANENTLY:
                # redirection result
                return False
            else:
                response.raise_for_status()

    async def _search_for(self, item, result_mapping):
        item = re.sub(r'\W+', '_', item).strip('_')
        query = quote(item)
        first_alphanum_char = self._query_first_alpha_num(item)
        url = f'{SEARCH_BASE_URI}/suggestion/x/{query}.json'

        results = await self._get(url=url, query=query)
        return [{name: res.get(key, None)
                 for name, key in result_mapping.items()}
                for res in results.get('d', [])]

    @logit
    async def search_for_name(self, name):
        mapping = {'name': 'l', 'imdb_id': 'id'}
        return [res for res in await self._search_for(name, mapping)
                if res['imdb_id'].startswith('nm')]

    @logit
    async def search_for_title(self, title):
        mapping = {'title': 'l', 'year': 'y', 'imdb_id': 'id', 'type': 'q'}
        return await self._search_for(title, mapping)

    async def get_popular_titles(self):
        return await self._get_resource('/chart/titlemeter')

    async def get_popular_shows(self):
        return await self._get_resource('/chart/tvmeter')

    async def get_popular_movies(self):
        return await self._get_resource('/chart/moviemeter')

    @logit
    async def _fetch(self, name, uri, imdb_id):
        if name.startswith('get_title'):
            await self._redirection_title_check(imdb_id)

        self.validate_imdb_id(imdb_id)
        return await self._get_resource(uri.format(imdb_id=imdb_id))

    @logit
    async def get_title_episodes(self, imdb_id):
        self.validate_imdb_id(imdb_id)
        if self.exclude_episodes:
            raise ValueError('exclude_episodes is current set to true')
        return await self._get_resource(f'/title/{imdb_id}/episodes')

    @logit
    async def get_title_episodes_detailed(self, imdb_id, season, limit=500,
                                          region=None, offset=0):
        """
        Request detailed information for a tv series, for a specific season.
        :param imdb_id: The imdb id including the TT prefix.
        :param limit: Limit the amound of episodes returned for a season.
        :param region: Two capital letter region code in ISO 3166-1 alpha-2.
        :param season: The season you want the detailed information for.
        :param offset: Offset episode results by this value.
        """
        self.validate_imdb_id(imdb_id)
        if season < 1:
            raise ValueError('season must be greater than zero')
        params = {
            'end': limit,
            'start': offset,
            'season': season - 1,  # api seasons are zero indexed
            'tconst': imdb_id,
        }
        if region:
            params.update({'region': region})

        url = urljoin(BASE_URI,
                      '/template/imdb-ios-writable/tv-episodes-v2.jstl/render')
        return await self._get(url, params=params)

    async def get_title_top_crew(self, imdb_id):
        """
        Request detailed information about title's top crew (ie: directors,
        writters, etc.).
        :param imdb_id: The imdb id including the TT prefix.
        """
        logger.info('called get_title_top_crew %s', imdb_id)

        self.validate_imdb_id(imdb_id)

        params = {
            'tconst': imdb_id,
        }

        url = urljoin(
            BASE_URI,
            '/template/imdb-android-writable/7.3.top-crew.jstl/render')
        return await self._get(url, params=params)

    @staticmethod
    def _cache_response(file_path, resp):
        with open(file_path, 'w+') as f:
            json.dump(resp, f)

    @staticmethod
    def _parse_dirty_json(data, query=None):
        if query is None:
            match_json_within_dirty_json = r'imdb\$.+\({1}(.+)\){1}'
        else:
            query_match = ''.join(
                char if char.isalnum() else f'[{char}]'
                for char in unquote(query)
            )
            query_match = query_match.replace('[ ]', '.+')
            match_json_within_dirty_json = (
                r'imdb\${}\((.+)\)'.format(query_match)
            )
        data_clean = re.match(
            match_json_within_dirty_json, data, re.IGNORECASE
        ).groups()[0]
        return json.loads(data_clean)

    @staticmethod
    def validate_imdb_id(imdb_id):
        match_id = r'[a-zA-Z]{2}[0-9]{7}'
        try:
            re.match(match_id, imdb_id, re.IGNORECASE).group()
        except (AttributeError, TypeError):
            raise ValueError('invalid imdb id')

    @staticmethod
    def _is_redirection_result(response):
        """
        Return True if response is that of a redirection else False
        Redirection results have no information of use.
        """
        imdb_id = response['data'].get('tconst')
        if (
            imdb_id and
            imdb_id != response['data'].get('news', {}).get('channel')
        ):
            return True
        return False

    async def _get_resource(self, path):
        url = f'{BASE_URI}{path}'
        data = await self._get(url=url)
        return data['resource']

    async def _get(self, url, query=None, params=None):
        path = urlparse(url).path
        if params:
            path += '?' + urlencode(params)
        headers = {'Accept-Language': self.locale}
        headers.update(await self.get_auth_headers(path))

        async with self.session.get(url, headers=headers, params=params) as r:
            if not r.status == HTTPStatus.OK:
                if r.status == HTTPStatus.NOT_FOUND:
                    raise LookupError(f'Resource {path} not found')
                else:
                    msg = f'{r.status} {r.text}'
                    raise ImdbAPIError(msg)
            resp_data = await r.text(encoding='utf-8')
        try:
            resp_dict = json.loads(resp_data)
        except ValueError:
            resp_dict = self._parse_dirty_json(data=resp_data, query=query)

        if resp_dict.get('error'):
            return None
        return resp_dict

    async def _redirection_title_check(self, imdb_id):
        if await self.is_redirection_title(imdb_id):
            self._title_not_found(msg=f'{imdb_id} is a redirection imdb id')

    async def is_redirection_title(self, imdb_id):
        self.validate_imdb_id(imdb_id)
        page_url = f'https://www.imdb.com/title/{imdb_id}/'
        async with self.session.head(page_url) as response:
            if response.status == HTTPStatus.MOVED_PERMANENTLY:
                return True
            else:
                return False

    def _query_first_alpha_num(self, query):
        for char in query.lower():
            if char.isalnum():
                return char
        raise ValueError(
            'invalid query, does not contain any alphanumeric characters'
        )

    def _title_not_found(self, msg=''):
        if msg:
            msg = f' {msg}'
        raise LookupError(f'Title not found.{msg}')
