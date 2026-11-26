//! The demo shop's data and the secrets an exploit reveals. The oracle confirms a
//! vulnerability when one of these markers comes back in a response.

/// A product the shop hides (`hidden = 1`); listing it means the WHERE clause was broken.
pub const HIDDEN_PRODUCT: &str = "Prototype grinder X-9 (unreleased)";
/// The admin's password hash in `users`; seeing it means a UNION read another table.
pub const ADMIN_HASH: &str = "$2y$10$Jq7vK0bZ1rT9mWcXeYpQ8uO4nD5sL2hG6fA3kB8iV0wE1zR7tN9yS";

/// `products`: (id, name, price, hidden).
pub const PRODUCTS: &[(i64, &str, f64, i64)] = &[
    (1, "Espresso cup", 9.5, 0),
    (2, "Burr grinder", 89.0, 0),
    (3, "Milk jug", 14.0, 0),
    (4, HIDDEN_PRODUCT, 999.0, 1),
    (5, "Pour-over kettle", 39.0, 0),
];

/// `users`: (id, username, password_hash, email).
pub const USERS: &[(i64, &str, &str, &str)] = &[
    (1, "admin", ADMIN_HASH, "admin@shop.example"),
    (
        2,
        "alice",
        "$2y$10$8cQ1nZ4rT7yU0iO3pA6sD9fG2hJ5kL8zX1cV4bN7mQ0wE3rT6yU9i",
        "alice@shop.example",
    ),
    (
        3,
        "mallory",
        "$2y$10$Z9xW8vU7tS6rQ5pO4nM3lK2jI1hG0fE9dC8bA7zY6xW5vU4tS3rQ2",
        "mallory@shop.example",
    ),
];

/// The attacker's own account (`[[logins]]` and BOLA scenarios): a real customer.
pub const ATTACKER_USER: &str = "mallory";
pub const ATTACKER_TOKEN: &str = "tok-mallory-6c1f02";

/// The admin's password: a seasonal password, the 12th guess of the attacker's list.
pub const ADMIN_PASSWORD: &str = "Autumn2026!";

/// Orders `/api/orders/{id}` serves: ids 1000..1200, owners assigned by a fixed rule;
/// the attacker owns 1002 and 1077.
pub const ORDER_FIRST: i64 = 1000;
pub const ORDER_COUNT: i64 = 200;
const CUSTOMERS: &[&str] = &["alice", "bob", "carol", "dave", "erin", "frank", "grace"];

pub fn order_owner(id: i64) -> Option<&'static str> {
    if !(ORDER_FIRST..ORDER_FIRST + ORDER_COUNT).contains(&id) {
        return None;
    }
    if id == 1002 || id == 1077 {
        return Some(ATTACKER_USER);
    }
    let h = (id as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 59;
    Some(CUSTOMERS[h as usize % CUSTOMERS.len()])
}

/// The order as the API returns it.
pub fn order_json(id: i64) -> Option<String> {
    let owner = order_owner(id)?;
    let cents = (id * 7919) % 20_000 + 500;
    Some(
        serde_json::json!({
            "id": id,
            "owner": owner,
            "total": format!("{}.{:02}", cents / 100, cents % 100),
            "ship_to": format!("{} {}, {} Example Street", owner, id % 97, id % 31 + 1),
        })
        .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders_have_owners_and_the_attacker_owns_two() {
        let mine = (ORDER_FIRST..ORDER_FIRST + ORDER_COUNT)
            .filter(|&i| order_owner(i) == Some(ATTACKER_USER))
            .count();
        assert_eq!(mine, 2);
        assert!(order_owner(999).is_none() && order_owner(1200).is_none());
        assert!(order_json(1001).unwrap().contains("\"owner\""));
    }
}
