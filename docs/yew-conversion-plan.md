# OxidizedOasis-WebSands: Planned Conversion to Yew Frontend

## Objective

This document outlines the proposed plan for converting OxidizedOasis-WebSands from static HTML files to a Yew-based frontend. The primary goals are:

1. Implement a more dynamic frontend using Rust
2. Maintain consistency between frontend and backend technologies
3. Potentially improve performance through WebAssembly compilation

## Proposed Methodology

### 1. Project Restructuring

The project structure will be modified to accommodate the Yew frontend:

```
oxidizedoasis-websands/
├── Cargo.toml
├── src/  (backend code)
├── frontend/
│   ├── Cargo.toml
│   ├── index.html
│   ├── src/
│   └── static/
└── dist/  (for generated Yew output)
```

### 2. Dependency Management

Yew and associated dependencies will be added to a new `frontend/Cargo.toml`:

```toml
[dependencies]
yew = "0.19"
wasm-bindgen = "0.2"
web-sys = "0.3"
```

### 3. Component Conversion

HTML elements will be systematically converted to Yew components. Example of planned conversion:

```rust
// frontend/src/components/nav.rs
use yew::prelude::*;

#[function_component(Nav)]
pub fn nav() -> Html {
    html! {
        <nav>
            <ul>
                <li><a href="/">{"Home"}</a></li>
                <li><a href="/login">{"Login"}</a></li>
                <li><a href="/about">{"About"}</a></li>
                <li><a href="/contact">{"Contact"}</a></li>
            </ul>
        </nav>
    }
}
```

### 4. Build Process Modification

The build process will be updated to include Yew compilation:

1. Install Trunk for Yew compilation: `cargo install trunk`
2. Create a build script to automate the process:

```bash
#!/bin/bash
cd frontend
trunk build --release
cd ..
cargo build --release
```

### 5. Backend Modification

The Actix-Web backend will be modified to serve the Yew frontend:

```rust
.service(fs::Files::new("/", "./dist").index_file("index.html"))
```

### 6. Routing Implementation

Routing will be implemented using `yew-router`:

```rust
use yew_router::prelude::*;

#[derive(Clone, Routable, PartialEq)]
enum Route {
    #[at("/")]
    Home,
    #[at("/login")]
    Login,
    #[at("/about")]
    About,
    #[not_found]
    #[at("/404")]
    NotFound,
}

fn switch(routes: &Route) -> Html {
    match routes {
        Route::Home => html! { <Home /> },
        Route::Login => html! { <Login /> },
        Route::About => html! { <About /> },
        Route::NotFound => html! { <h1>{"404"}</h1> },
    }
}
```

### 7. API Integration

API calls to the Actix-Web backend will be implemented using `web-sys` and `wasm-bindgen`:

```rust
use wasm_bindgen_futures::spawn_local;
use web_sys::RequestInit;

fn make_api_call() {
    spawn_local(async move {
        let mut opts = RequestInit::new();
        opts.method("GET");
        opts.mode(web_sys::RequestMode::Cors);

        let request = web_sys::Request::new_with_str_and_init("/api/data", &opts).unwrap();

        let window = web_sys::window().unwrap();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await.unwrap();
        let resp: Response = resp_value.dyn_into().unwrap();

        let json = JsFuture::from(resp.json().unwrap()).await.unwrap();
        // Handle the response...
    });
}
```

## Expected Outcomes

1. A more integrated frontend-backend system, with Rust used throughout the stack.
2. Potential performance improvements due to WebAssembly compilation (to be verified through benchmarking).
3. Better code organization and reusability through Yew's component-based architecture.

## Anticipated Challenges and Proposed Solutions

1. **Challenge**: Integrating Yew build process with existing Actix-Web backend.
   **Proposed Solution**: Create a custom build script to automate both frontend and backend compilation.

2. **Challenge**: Managing state between components.
   **Proposed Solution**: Utilize Yew's built-in `use_state` hook for simple state management. For more complex state, consider implementing a custom state management solution.

3. **Challenge**: Ensuring type safety in API calls between frontend and backend.
   **Proposed Solution**: Develop shared data structures between frontend and backend to ensure consistency.

## Future Considerations

1. Implement a comprehensive testing strategy for Yew components.
2. Optimize the build process for faster development iterations.
3. Explore advanced state management solutions for more complex UI interactions.

## Conclusion

The proposed conversion of OxidizedOasis-WebSands to a Yew frontend aims to create a more cohesive full-stack Rust application. While the process will require significant refactoring, it is expected to lay the groundwork for more dynamic and performant user interfaces. The success of this conversion will be evaluated based on performance metrics, code maintainability, and developer experience within the new framework.

## Next Steps

1. Set up a development branch for the Yew conversion.
2. Begin with a small prototype to test the integration of Yew with the existing backend.
3. Gradually convert existing pages to Yew components, starting with the simplest pages.
4. Conduct regular code reviews and testing throughout the conversion process.
5. Document challenges and solutions encountered during the implementation for future reference.
