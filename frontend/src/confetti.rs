use wasm_bindgen::prelude::*;
use web_sys::window;
use js_sys::Math;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = window)]
    fn confetti(options: &JsValue);
}

pub fn trigger_confetti() -> i32 {
    let window = window().expect("no global `window` exists");

    let confetti_rain = Closure::wrap(Box::new(move || {
        let options = js_sys::Object::new();
        js_sys::Reflect::set(&options, &"particleCount".into(), &JsValue::from(3)).unwrap();
        js_sys::Reflect::set(&options, &"angle".into(), &JsValue::from(90)).unwrap();
        js_sys::Reflect::set(&options, &"spread".into(), &JsValue::from(100)).unwrap();
        js_sys::Reflect::set(&options, &"origin".into(), &JsValue::from_str(&format!("{} 0", Math::random()))).unwrap();
        js_sys::Reflect::set(&options, &"gravity".into(), &JsValue::from(1)).unwrap();
        js_sys::Reflect::set(&options, &"drift".into(), &JsValue::from(0)).unwrap();
        js_sys::Reflect::set(&options, &"ticks".into(), &JsValue::from(300)).unwrap();

        confetti(&options);
    }) as Box<dyn Fn()>);

    // Set interval to call the function every 50ms
    let interval_id = window.set_interval_with_callback_and_timeout_and_arguments_0(
        confetti_rain.as_ref().unchecked_ref(),
        50
    ).expect("Failed to set interval");

    // Forget the closure to keep it alive
    confetti_rain.forget();

    // Return the interval ID
    interval_id
}