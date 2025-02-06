use yew::prelude::*;
use web_sys::DragEvent;

#[function_component(Data)]
pub fn data_page() -> Html {
    let file_input_ref = use_node_ref();

    // Handler for drag over: prevents default behavior.
    let on_drag_over = Callback::from(|e: DragEvent| {
        e.prevent_default();
    });

    // Handler for file drop.
    let on_drop = Callback::from(|e: DragEvent| {
        e.prevent_default();
        // TODO: Handle dropped files.
    });

    // Click handler to open file dialog.
    let on_upload_click = {
        let file_input_ref = file_input_ref.clone();
        Callback::from(move |_| {
            if let Some(input) = file_input_ref.cast::<web_sys::HtmlInputElement>() {
                input.click();
            }
        })
    };

    html! {
        <div class="c-card">
            <div class="c-card__header">
                <h2 class="c-card__title">{ "Upload Your Data Files" }</h2>
                <p class="c-card__subtitle">{ "Drag and drop files into the area below or click to select files for upload." }</p>
            </div>
            <div class="c-card__content">
                <section class="upload-section">
                    <div class="drag-drop-area"
                         ondragover={on_drag_over}
                         ondrop={on_drop}
                         onclick={on_upload_click.clone()}>
                        <p>{ "Drag and drop files here or click to select files" }</p>
                        <input type="file" multiple=true ref={file_input_ref} style="display: none;" />
                    </div>
                    <button class="upload-button" onclick={on_upload_click}>
                        { "Upload Files" }
                    </button>
                </section>
                <section class="summary-panel">
                    <div class="summary-card">
                        <h2>{ "Upload Summary" }</h2>
                        <p>{ "Storage Used: " }<span class="summary-value">{ "0 MB" }</span></p>
                        <p>{ "Files Uploaded: " }<span class="summary-value">{ "0" }</span></p>
                        <div class="file-type-breakdown">
                            <p>{ "File Types:" }</p>
                            <span class="file-badge">{ "PDF" }</span>
                            <span class="file-badge">{ "DOCX" }</span>
                            <span class="file-badge">{ "Images" }</span>
                            <span class="file-badge">{ "Others" }</span>
                        </div>
                    </div>
                </section>
            </div>
        </div>
    }
}
