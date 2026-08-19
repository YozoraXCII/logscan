const gallery = document.querySelector("#people-gallery");

function noImage() {
  const element = document.createElement("div");
  element.className = "no-image";
  element.textContent = "No TMDb images found";
  return element;
}

function imageCard(image) {
  const tile = document.createElement("div");
  tile.className = "image-tile";
  const link = document.createElement("a");
  link.className = "person-image";
  link.href = image.download_url;
  link.target = "_blank";
  link.rel = "noopener";
  link.title = "View the original image";
  const imageElement = document.createElement("img");
  imageElement.src = image.preview_url;
  imageElement.alt = "TMDb profile image";
  imageElement.loading = "lazy";
  link.append(imageElement);
  const download = document.createElement("a");
  download.className = "image-download";
  download.href = image.download_url;
  download.download = "";
  download.target = "_blank";
  download.rel = "noopener";
  download.title = "Download original image";
  download.setAttribute("aria-label", "Download original image");
  download.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v11m0 0 4-4m-4 4-4-4M5 17v3h14v-3"/></svg>';
  tile.append(link, download);
  return tile;
}

async function complete(key, card) {
  if (!confirm("Mark this person complete and remove them from the backlog?")) return;
  const response = await fetch(`/api/people/${encodeURIComponent(key)}`, { method: "DELETE" });
  if (!response.ok) return alert("That person could not be removed.");
  card.remove();
  if (!gallery.children.length) gallery.textContent = "No missing people are waiting for images.";
}

async function addPerson(person) {
  const card = document.createElement("article");
  card.className = "person-card";
  const heading = document.createElement("h2");
  const page = document.createElement("a");
  page.href = `/people/${encodeURIComponent(person.key)}`;
  page.textContent = person.name;
  heading.append(page);
  const detail = document.createElement("p");
  detail.textContent = person.tmdb_id ? `TMDb ID: ${person.tmdb_id}` : "TMDb match not found";
  const images = document.createElement("div");
  images.className = "image-row";
  const actions = document.createElement("div");
  actions.className = "person-actions";
  const completeButton = document.createElement("button");
  completeButton.className = "danger-button";
  completeButton.textContent = "Mark complete";
  completeButton.addEventListener("click", () => complete(person.key, card));
  actions.append(completeButton);
  card.append(heading, detail, images, actions);
  gallery.append(card);
  try {
    const response = await fetch(`/api/people/${encodeURIComponent(person.key)}/images?limit=5`);
    const data = await response.json();
    (data.images || []).forEach((image) => images.append(imageCard(image)));
    if (!data.images?.length) images.append(noImage());
  } catch { images.append(noImage()); }
}

fetch("/api/people").then((response) => response.json()).then(async ({ people }) => {
  if (!people.length) { gallery.textContent = "No missing people are waiting for images."; return; }
  for (const person of people) await addPerson(person);
}).catch(() => { gallery.textContent = "Unable to load missing people."; });
