#![no_std]

use core::{convert::Infallible, panic::PanicInfo};
use soroban_env_guest::{EnvBase, Guest, Val};

#[export_name = "_"]
static METADATA_EXPORT: () = ();

#[link_section = "contractenvmetav0"]
#[used]
static ENVIRONMENT_METADATA: [u8; soroban_env_guest::meta::XDR.len()] =
    soroban_env_guest::meta::XDR;

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}

fn infallible<T>(result: Result<T, Infallible>) -> T {
    match result {
        Ok(value) => value,
        Err(never) => match never {},
    }
}

fn old_dense_map(env: &Guest) -> soroban_env_guest::MapObject {
    infallible(env.map_new_from_slices(
        &["owner", "value"],
        &[Val::from_u32(10).into(), Val::from_u32(20).into()],
    ))
}

fn new_sparse_map(env: &Guest, optional: Val) -> soroban_env_guest::MapObject {
    infallible(env.sparse_map_new_from_slices(
        &["extra", "owner", "value"],
        &[optional, Val::from_u32(10).into(), Val::from_u32(20).into()],
    ))
}

fn as_vector(env: &Guest, values: &[Val]) -> u64 {
    let vector = infallible(env.vec_new_from_slice(values));
    Val::from(vector).get_payload()
}

#[export_name = "old_to_new_sparse"]
pub extern "C" fn old_to_new_sparse() -> u64 {
    let env = Guest;
    let map = old_dense_map(&env);
    let mut output = [
        Val::from_u32(71).into(),
        Val::from_u32(72).into(),
        Val::from_u32(77).into(),
    ];
    infallible(env.sparse_map_unpack_to_slice(map, &["extra", "owner", "value"], &mut output));
    as_vector(&env, &output)
}

#[export_name = "old_to_new_dense"]
pub extern "C" fn old_to_new_dense() -> u64 {
    let env = Guest;
    let map = old_dense_map(&env);
    let mut output = [
        Val::from_u32(71).into(),
        Val::from_u32(72).into(),
        Val::from_u32(77).into(),
    ];
    infallible(env.map_unpack_to_slice(map, &["extra", "owner", "value"], &mut output));
    as_vector(&env, &output)
}

#[export_name = "new_none_to_old_dense"]
pub extern "C" fn new_none_to_old_dense() -> u64 {
    let env = Guest;
    let map = new_sparse_map(&env, Val::VOID.into());
    let mut output = [Val::from_u32(71).into(), Val::from_u32(72).into()];
    infallible(env.map_unpack_to_slice(map, &["owner", "value"], &mut output));
    as_vector(&env, &output)
}

#[export_name = "new_some_to_old_dense"]
pub extern "C" fn new_some_to_old_dense() -> u64 {
    let env = Guest;
    let map = new_sparse_map(&env, Val::from_u32(30).into());
    let mut output = [Val::from_u32(71).into(), Val::from_u32(72).into()];
    infallible(env.map_unpack_to_slice(map, &["owner", "value"], &mut output));
    as_vector(&env, &output)
}

#[export_name = "new_some_to_new_sparse"]
pub extern "C" fn new_some_to_new_sparse() -> u64 {
    let env = Guest;
    let map = new_sparse_map(&env, Val::from_u32(30).into());
    let mut output = [Val::VOID.into(), Val::VOID.into(), Val::VOID.into()];
    infallible(env.sparse_map_unpack_to_slice(map, &["extra", "owner", "value"], &mut output));
    as_vector(&env, &output)
}
