//! Public vocabulary construction and value-trait contract.

use alloc::borrow::Cow;
use core::fmt::Debug;

use keri_events::{KeriEvent, SadBlock};

extern crate alloc;

const fn assert_value_traits<T: Clone + Debug + PartialEq + Eq>() {}

#[test]
fn public_data_contract_is_explicit_without_feature_unification() {
    assert_value_traits::<KeriEvent<'static>>();

    let raw = SadBlock::new_unchecked(Cow::Borrowed("{}"));
    assert_eq!(raw.payload(), "{}");
    assert_eq!(raw.clone(), raw);
}
