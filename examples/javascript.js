// Synthetic static-discovery input: parse this file, do not execute it.
// All values are placeholders; runtime reachability is deliberately unproven.
import axios from 'axios';

const api = axios.create({baseURL: '/api'});
api.post('/orders', {amount: input.amount, ownerId: input.owner, items: [{sku: input.sku}]});
api.post('/graphql', {
  query: 'query ReadOrder($id: ID!) { order(id: $id) { id } }',
  variables: {id: input.orderId},
});
fetch(`/unresolved/${input.dynamicId}`);
