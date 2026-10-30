2026-10-30

- Anonymous requester can GET /recipes and see all recipes, including ones with "is_public": false.
- Anonymous requester can PATCH /recipes/1 to change the title (server returns 200 OK and saves the change).
- Anonymous requester can DELETE /recipes/2 (server returns 204 NO CONTENT and recipe 2 disappears from the list).