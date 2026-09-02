/**
 * Handing a file to the browser, from data the page already holds.
 *
 * Generic on purpose: the operations panel exports plain text and the console exports JSON, and both
 * are the same three lines. The MIME type is a parameter rather than a second copy of them.
 */
export function downloadFile(filename: string, content: string, mimeType = 'text/plain') {
  const url = URL.createObjectURL(new Blob([content], { type: mimeType }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
