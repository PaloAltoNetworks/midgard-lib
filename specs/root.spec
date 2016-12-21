{
    "attributes": [],
    "children": [
        {
            "bulk_create": false,
            "bulk_delete": false,
            "bulk_update": false,
            "create": false,
            "delete": false,
            "deprecated": null,
            "get": true,
            "relationship": "root",
            "rest_name": "auth",
            "update": false
        },
        {
            "bulk_create": false,
            "bulk_delete": false,
            "bulk_update": false,
            "create": true,
            "delete": false,
            "deprecated": null,
            "get": false,
            "relationship": "root",
            "rest_name": "issue",
            "update": false
        }
    ],
    "model": {
        "create": false,
        "delete": false,
        "description": "Root object of the API",
        "entity_name": "Root",
        "extends": [
            "@base"
        ],
        "get": true,
        "package": "midgard",
        "resource_name": "root",
        "rest_name": "root",
        "root": true,
        "update": false
    }
}