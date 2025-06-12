use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct Waypoint {
    pub x: f64, // Representing longitude or a general X coordinate
    pub y: f64, // Representing latitude or a general Y coordinate
    pub altitude: f64,
    pub name: String,
}

#[derive(Clone, PartialEq, Properties)]
pub struct FlightPath {
    pub waypoints: Vec<Waypoint>,
}

#[derive(Clone, PartialEq, Properties)]
pub struct FlightPathVisualizerProps {
    pub path: FlightPath,
    #[prop_or(800)]
    pub width: usize,
    #[prop_or(600)]
    pub height: usize,
}

#[function_component(FlightPathVisualizer)]
pub fn flight_path_visualizer(props: &FlightPathVisualizerProps) -> Html {
    let path_data = if props.path.waypoints.len() < 2 {
        String::new()
    } else {
        props.path.waypoints.iter()
            .map(|wp| format!("L {} {}", wp.x, props.height as f64 - wp.altitude)) // Invert Y for altitude
            .collect::<Vec<String>>()
            .join(" ")
            .replacen('L', "M", 1) // Start with Move to command
    };

    html! {
        <svg class="flight-path-visualizer" width={props.width.to_string()} height={props.height.to_string()} viewBox={format!("0 0 {} {}", props.width, props.height)}>
            if !path_data.is_empty() {
                <path d={path_data.clone()} class="flight-path-line" />
            }
            { for props.path.waypoints.iter().map(|wp| html! {
                <g class="waypoint-group">
                    <circle cx={wp.x.to_string()} cy={(props.height as f64 - wp.altitude).to_string()} r="5" class="waypoint-marker" />
                    <text x={(wp.x + 8.0).to_string()} y={(props.height as f64 - wp.altitude + 5.0).to_string()} class="waypoint-label">{ &wp.name }</text>
                    // Basic hover: title attribute (more advanced would need JS/CSS)
                    <title>{format!("Waypoint: {}\nAltitude: {}m", wp.name, wp.altitude)}</title>
                </g>
            })}
            // Placeholder for altitude lines (simplified)
            { for (0..=5).map(|i| {
                let y_pos = (props.height as f64 / 5.0) * i as f64;
                html!{
                    <line x1="0" y1={y_pos.to_string()} x2={props.width.to_string()} y2={y_pos.to_string()} class="altitude-grid-line" />
                }
            })}
        </svg>
    }
}
