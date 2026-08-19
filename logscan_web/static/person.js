const container = document.querySelector("#person-detail");

function noImage() { const e = document.createElement("div"); e.className = "no-image"; e.textContent = "No TMDb images found"; return e; }
function imageCard(image) { const tile = document.createElement("div"); tile.className = "image-tile"; const a = document.createElement("a"); a.className = "person-image"; a.href = image.download_url; a.target = "_blank"; a.rel = "noopener"; a.title = "View the original image"; const img = document.createElement("img"); img.src = image.preview_url; img.alt = "TMDb profile image"; img.loading = "lazy"; a.append(img); const download = document.createElement("a"); download.className = "image-download"; download.href = image.download_url; download.download = ""; download.target = "_blank"; download.rel = "noopener"; download.title = "Download original image"; download.setAttribute("aria-label", "Download original image"); download.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v11m0 0 4-4m-4 4-4-4M5 17v3h14v-3"/></svg>'; tile.append(a, download); return tile; }

fetch(`/api/people/${encodeURIComponent(window.PERSON_KEY)}/images`).then((response) => response.json()).then(({ person, images }) => {
  const title = document.createElement("h1"); title.textContent = person.name;
  const detail = document.createElement("p"); detail.className = "hero-copy"; detail.textContent = person.tmdb_id ? `TMDb ID: ${person.tmdb_id}. Select an image to open or download its original version.` : "TMDb did not return a matching person or any images.";
  const complete = document.createElement("button"); complete.className = "danger-button"; complete.textContent = "Mark complete";
  complete.addEventListener("click", async () => { if (!confirm("Remove this person from the backlog?")) return; const response = await fetch(`/api/people/${encodeURIComponent(person.key)}`, { method: "DELETE" }); if (response.ok) location.href = "/people"; else alert("That person could not be removed."); });
  const gallery = document.createElement("section"); gallery.className = "image-gallery"; images.forEach((image) => gallery.append(imageCard(image))); if (!images.length) gallery.append(noImage());
  container.append(title, detail, complete, gallery);
}).catch(() => { container.textContent = "Unable to load this person."; });
