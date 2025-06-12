// frontend/src/components/drone/flight_path_tests.rs
#![cfg(test)] // Only compile when running tests

use super::flight_path::*; // Import the module we want to test
use yew::prelude::*;

// Helper function to create a sample flight path
fn sample_flight_path_1() -> FlightPath {
    FlightPath {
        waypoints: vec![
            Waypoint { x: 50.0, y: 0.0, altitude: 50.0, name: "WP1".to_string() },
            Waypoint { x: 150.0, y: 0.0, altitude: 100.0, name: "WP2".to_string() },
            Waypoint { x: 250.0, y: 0.0, altitude: 75.0, name: "WP3".to_string() },
        ],
    }
}

fn sample_flight_path_empty() -> FlightPath {
    FlightPath {
        waypoints: vec![],
    }
}

fn sample_flight_path_single_wp() -> FlightPath {
    FlightPath {
        waypoints: vec![
            Waypoint { x: 50.0, y: 0.0, altitude: 50.0, name: "WP_SINGLE".to_string() },
        ],
    }
}

// Helper to get a string representation of the rendered HTML for basic checks.
// In a real scenario with wasm-bindgen-test, you'd render to the DOM and inspect.
fn render_component_to_string(props: FlightPathVisualizerProps) -> String {
    // This is a simplified way to get some output for basic string checks.
    // Yew's testing typically involves wasm-bindgen-test and a browser context
    // to inspect actual DOM elements.
    let renderer = yew::ServerRenderer::<FlightPathVisualizer>::with_props(props);
    renderer.render()
}

#[test]
fn test_visualizer_renders_with_path() {
    let props = FlightPathVisualizerProps {
        path: sample_flight_path_1(),
        width: 800,
        height: 600,
    };
    let rendered_html = render_component_to_string(props);

    // Basic checks:
    // 1. Path data generation (simplified check for "M" and "L")
    //    Altitude is props.height - wp.altitude. For WP1: 600 - 50 = 550. For WP2: 600 - 100 = 500
    assert!(rendered_html.contains("d=\"M 50 550 L 150 500 L 250 525\""), "Path data string not found or incorrect.");

    // 2. Waypoint markers (check for circle elements and their positions)
    assert!(rendered_html.contains("<circle cx=\"50\" cy=\"550\" r=\"5\" class=\"waypoint-marker\">"), "WP1 marker not found or incorrect.");
    assert!(rendered_html.contains("<circle cx=\"150\" cy=\"500\" r=\"5\" class=\"waypoint-marker\">"), "WP2 marker not found or incorrect.");
    assert!(rendered_html.contains("<circle cx=\"250\" cy=\"525\" r=\"5\" class=\"waypoint-marker\">"), "WP3 marker not found or incorrect.");

    // 3. Waypoint labels
    assert!(rendered_html.contains("<text x=\"58\" y=\"555\" class=\"waypoint-label\">WP1</text>"), "WP1 label not found or incorrect.");
    assert!(rendered_html.contains("<text x=\"158\" y=\"505\" class=\"waypoint-label\">WP2</text>"), "WP2 label not found or incorrect.");
    assert!(rendered_html.contains("<text x=\"258\" y=\"525\" class=\"waypoint-label\">WP3</text>"), "WP3 label not found or incorrect.");

    // 4. Altitude display accuracy (checked via cy attributes and path data) - implicitly tested above
    // 5. Interaction handling (hover states are CSS based, difficult to test here without browser context)
    //    The <title> element provides a basic check for hover text content.
    assert!(rendered_html.contains("<title>Waypoint: WP1\\nAltitude: 50m</title>"), "WP1 title for hover not found.");
}

#[test]
fn test_visualizer_renders_with_empty_path() {
    let props = FlightPathVisualizerProps {
        path: sample_flight_path_empty(),
        width: 800,
        height: 600,
    };
    let rendered_html = render_component_to_string(props);

    // Should not contain path data or waypoint markers if path is empty
    assert!(!rendered_html.contains("class=\"flight-path-line\""), "Path line should not exist for empty path.");
    assert!(!rendered_html.contains("class=\"waypoint-marker\""), "Waypoint markers should not exist for empty path.");
    // Grid lines should still be there
    assert!(rendered_html.contains("class=\"altitude-grid-line\""), "Altitude grid lines should exist.");
}

#[test]
fn test_visualizer_renders_with_single_waypoint_path() {
    let props = FlightPathVisualizerProps {
        path: sample_flight_path_single_wp(),
        width: 800,
        height: 600,
    };
    let rendered_html = render_component_to_string(props);

    // Path line should not be drawn for a single waypoint
    assert!(!rendered_html.contains("class=\"flight-path-line\""), "Path line should not exist for a single waypoint.");

    // Single waypoint marker and label should exist
    assert!(rendered_html.contains("<circle cx=\"50\" cy=\"550\" r=\"5\" class=\"waypoint-marker\">"), "Single WP marker not found or incorrect.");
    assert!(rendered_html.contains("<text x=\"58\" y=\"555\" class=\"waypoint-label\">WP_SINGLE</text>"), "Single WP label not found or incorrect.");
    assert!(rendered_html.contains("<title>Waypoint: WP_SINGLE\\nAltitude: 50m</title>"), "Single WP title for hover not found.");
}

// Potential future tests if environment allows:
// - Test path smoothing if more advanced algorithm is used.
// - Test interactive hover states more deeply (e.g., by simulating events and checking style changes).
// - Test altitude display accuracy by checking specific grid line positions if they were more dynamic.
