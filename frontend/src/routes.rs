// frontend/src/routes.rs
use yew_router::prelude::*;

#[derive(Clone, Routable, PartialEq)]
pub enum Route {
    #[at("/")]
    Home,
    #[at("/login")]
    Login,
    #[at("/about")]
    About,
    #[at("/dashboard")]
    Dashboard,
    #[not_found]
    #[at("/404")]
    NotFound,
}