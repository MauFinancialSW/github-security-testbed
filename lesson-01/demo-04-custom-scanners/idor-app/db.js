/**
 * Database Module (Mock)
 * ======================
 * Course: GitHub Copilot for Cybersecurity Specialists
 *
 * This is a mock database module for demonstration purposes.
 * In production, replace with actual database connection.
 */

// Mock data store
const mockData = {
  users: [
    {
      id: 1,
      tenant_id: 'tenant_a',
      email: 'alice@tenant-a.com',
      name: 'Alice Smith',
      phone: '555-0101',
      address: '123 Main St',
      ssn_last_four: '1234',
      role: 'user'
    },
    {
      id: 2,
      tenant_id: 'tenant_a',
      email: 'bob@tenant-a.com',
      name: 'Bob Johnson',
      phone: '555-0102',
      address: '456 Oak Ave',
      ssn_last_four: '5678',
      role: 'admin'
    },
    {
      id: 3,
      tenant_id: 'tenant_b',
      email: 'charlie@tenant-b.com',
      name: 'Charlie Brown',
      phone: '555-0201',
      address: '789 Pine Rd',
      ssn_last_four: '9012',
      role: 'user'
    },
    {
      id: 4,
      tenant_id: 'tenant_b',
      email: 'diana@tenant-b.com',
      name: 'Diana Prince',
      phone: '555-0202',
      address: '321 Elm St',
      ssn_last_four: '3456',
      role: 'admin'
    }
  ],
  documents: [
    {
      id: 1,
      tenant_id: 'tenant_a',
      user_id: 1,
      title: 'Tenant A - Q1 Financial Report',
      content: 'Confidential financial data for Tenant A...',
      created_at: '2024-01-15',
      updated_at: '2024-01-20'
    },
    {
      id: 2,
      tenant_id: 'tenant_a',
      user_id: 1,
      title: 'Tenant A - Employee Records',
      content: 'Sensitive employee information...',
      created_at: '2024-02-01',
      updated_at: '2024-02-01'
    },
    {
      id: 3,
      tenant_id: 'tenant_b',
      user_id: 3,
      title: 'Tenant B - Strategic Plan 2024',
      content: 'Top secret strategic initiatives...',
      created_at: '2024-01-10',
      updated_at: '2024-01-25'
    },
    {
      id: 4,
      tenant_id: 'tenant_b',
      user_id: 4,
      title: 'Tenant B - Customer Database Export',
      content: 'Customer PII and contact information...',
      created_at: '2024-02-05',
      updated_at: '2024-02-05'
    }
  ],
  invoices: [
    {
      id: 1,
      tenant_id: 'tenant_a',
      amount: 15000.00,
      status: 'paid',
      due_date: '2024-02-28'
    },
    {
      id: 2,
      tenant_id: 'tenant_b',
      amount: 25000.00,
      status: 'pending',
      due_date: '2024-03-15'
    }
  ],
  orders: [
    {
      id: 1,
      tenant_id: 'tenant_a',
      product: 'Enterprise License',
      quantity: 100,
      total: 50000.00
    },
    {
      id: 2,
      tenant_id: 'tenant_b',
      product: 'Professional License',
      quantity: 50,
      total: 25000.00
    }
  ]
};

// Mock query function
async function query(sql, params = []) {
  // Simulate async database query
  await new Promise(resolve => setTimeout(resolve, 10));

  // Parse simple SQL patterns (mock implementation)
  const selectMatch = sql.match(/SELECT .* FROM (\w+)(?: WHERE (.*))?/i);
  const updateMatch = sql.match(/UPDATE (\w+) SET .* WHERE id = \?/i);
  const deleteMatch = sql.match(/DELETE FROM (\w+) WHERE id = \?/i);

  if (selectMatch) {
    const table = selectMatch[1];
    const data = mockData[table] || [];

    if (selectMatch[2]) {
      // Simple WHERE clause handling
      if (selectMatch[2].includes('id = ?')) {
        const id = parseInt(params[0]);
        return data.filter(row => row.id === id);
      }
      if (selectMatch[2].includes('tenant_id = ?')) {
        return data.filter(row => row.tenant_id === params[0]);
      }
      if (selectMatch[2].includes('IN (?)')) {
        const ids = params[0].map(id => parseInt(id));
        return data.filter(row => ids.includes(row.id));
      }
    }

    return data;
  }

  if (updateMatch || deleteMatch) {
    return { affectedRows: 1 };
  }

  return [];
}

module.exports = { query };
