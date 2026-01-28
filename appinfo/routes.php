<?php
declare(strict_types=1);

return [
  'routes' => [
    ['name' => 'saml#login',     'url' => '/saml/login',     'verb' => 'GET'],
    ['name' => 'saml#logout',    'url' => '/saml/logout',    'verb' => 'GET'],
    ['name' => 'saml#loggedout', 'url' => '/saml/loggedout', 'verb' => 'GET'],
    ['name' => 'saml#noaccess',  'url' => '/saml/noaccess',  'verb' => 'GET'],
    ['name' => 'saml#metadata',  'url' => '/saml/metadata',  'verb' => 'GET'],
    ['name' => 'saml#acs',       'url' => '/saml/acs',       'verb' => 'POST'],
    ['name' => 'saml#sls',       'url' => '/saml/sls',       'verb' => 'GET'],
    ['name' => 'saml#sls_post',  'url' => '/saml/sls',       'verb' => 'POST'],
  ],
];
