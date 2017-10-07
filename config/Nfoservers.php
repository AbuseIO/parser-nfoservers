<?php

return [
    'parser' => [
        'name'          => 'Nfoservers',
        'enabled'       => true,
        'sender_map'    => [
            '/ddos-response@nfoservers.com/',
        ],
        'body_map'      => [
            //
        ],
    ],

    'feeds' => [
        'dns_resolver' => [
            'class'     => 'OPEN_DNS_RESOLVER',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'Source-IP',
            ],
        ],
        'ntp_server' => [
            'class'     => 'OPEN_NTP_SERVER',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'Source-IP',
            ],
        ],
        'compromised_host' => [
            'class'     => 'COMPROMISED_SERVER',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'Source-IP',
            ],
        ],
        'portmapper' => [
            'class'     => 'OPEN_PORTMAP_SERVER',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'Source-IP',
            ],
        ],
        'chargen' => [
            'class'     => 'OPEN_CHARGEN_SERVER',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'Source-IP',
            ],
        ],
        'ssdp' => [
            'class'     => 'OPEN_SSDP_SERVER',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'Source-IP',
            ],
        ],
        'default' => [
            'class'     => 'DEFAULT',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'Source-IP',
            ],
        ],

    ],
];
