function(task, responses) {
    if (task.status.includes("error")) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return { 'plaintext': combined };
    } else if (responses.length > 0) {
        let data = "";
        try {
            data = JSON.parse(responses[0]);
        } catch (error) {
            return { 'plaintext': responses[0] };
        }
        let output = "";
        if (data["total_chunks"] !== undefined) {
            output += "Total Chunks: " + data["total_chunks"] + "\n";
        }
        if (data["chunk_num"] !== undefined) {
            output += "Chunk Number: " + data["chunk_num"] + "\n";
        }
        if (data["file_id"] !== undefined) {
            output += "File ID: " + data["file_id"] + "\n";
        }
        if (data["filename"] !== undefined) {
            output += "Filename: " + data["filename"] + "\n";
        }
        return { 'plaintext': output };
    }
    return { 'plaintext': "No response yet from agent..." };
}
