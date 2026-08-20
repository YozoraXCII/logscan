const gallery = document.querySelector("#people-gallery");
const pagination = document.querySelector("#popular-pagination");
const { imageCard, noImage } = window.PeopleImages;
const page = Number(new URLSearchParams(location.search).get("page")) || 1;

function addImage(images, image, label, missingMessage, name) {
  images.append(image ? imageCard({ ...image, label, alt: `${name} ${label}` }) : noImage(missingMessage));
}

function googleImageSearchTile(name) {
  const parameters = new URLSearchParams({
    q: name,
    as_st: "y",
    imgar: "t|xt",
    udm: "2",
    tbs: "itp:face,qdr:y",
  });
  const link = document.createElement("a");
  link.className = "image-tile google-image-search-tile";
  link.href = `https://www.google.co.uk/search?${parameters}`;
  link.target = "_blank";
  link.rel = "noopener";
  const image = document.createElement("img");
  image.src = "/static/google.jpg";
  image.alt = "Google Image Search";
  image.loading = "lazy";
  const label = document.createElement("div");
  label.className = "image-label";
  label.textContent = "Google Image Search";
  link.append(image, label);
  return link;
}

function addPerson(person) {
  const card = document.createElement("article");
  card.className = "person-card";
  const controls = document.createElement("div");
  controls.className = "person-controls";
  if (person.flag_reason) card.classList.add("flagged-person");
  const exclude = document.createElement("button");
  exclude.className = "danger-button exclude-person";
  exclude.type = "button";
  exclude.title = "Exclude this person from Popular People";
  exclude.setAttribute("aria-label", `Exclude ${person.name}`);
  exclude.innerHTML = '<i class="fa-solid fa-ban" aria-hidden="true"></i>';
  exclude.addEventListener("click", async () => {
    const response = await fetch(`/api/people/popular/${encodeURIComponent(person.tmdb_id)}/exclude`, { method: "POST" });
    if (!response.ok) return alert("That person could not be excluded.");
    card.remove();
  });
  const check = document.createElement("button");
  check.className = "ok-person";
  check.type = "button";
  check.title = "Mark OK";
  check.setAttribute("aria-label", `Mark ${person.name} OK`);
  check.innerHTML = '<i class="fa-solid fa-check" aria-hidden="true"></i>';
  check.addEventListener("click", async () => {
    const response = await fetch(`/api/people/popular/${encodeURIComponent(person.tmdb_id)}/check`, { method: "POST" });
    if (!response.ok) return alert("That person could not be marked OK.");
    card.remove();
  });
  const flag = document.createElement("button");
  flag.className = "flag-person";
  flag.type = "button";
  flag.title = "Flag for Review";
  flag.setAttribute("aria-label", `Flag ${person.name} for review`);
  flag.innerHTML = '<i class="fa-solid fa-flag" aria-hidden="true"></i>';
  flag.addEventListener("click", async () => {
    const reason = await FlagDialog.show(person.name);
    if (!reason) return;
    const response = await fetch(`/api/people/popular/${encodeURIComponent(person.tmdb_id)}/flag`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason }),
    });
    if (!response.ok) return alert("That person could not be flagged.");
    location.href = "/people/popular?page=1";
  });
  controls.append(check, flag, exclude);
  const heading = document.createElement("h2");
  const link = document.createElement("a");
  link.href = `https://www.themoviedb.org/person/${encodeURIComponent(person.tmdb_id)}`;
  link.target = "_blank";
  link.rel = "noopener";
  link.textContent = person.name;
  heading.append(link);
  const detail = document.createElement("p");
  detail.append("TMDb ID: ");
  const idLink = document.createElement("a");
  idLink.href = `https://www.themoviedb.org/person/${encodeURIComponent(person.tmdb_id)}`;
  idLink.target = "_blank";
  idLink.rel = "noopener";
  idLink.textContent = person.tmdb_id;
  detail.append(idLink);
  const knownFor = document.createElement("p");
  knownFor.append("Known For: ", person.known_for_department || "Not specified");
  if (person.known_for?.length) {
    knownFor.append(" (");
    person.known_for.forEach((credit, index) => {
      if (index) knownFor.append(", ");
      const creditLink = document.createElement("a");
      creditLink.href = credit.url;
      creditLink.target = "_blank";
      creditLink.rel = "noopener";
      creditLink.textContent = credit.title;
      knownFor.append(creditLink);
    });
    knownFor.append(")");
  }
  const images = document.createElement("div");
  images.className = "image-row";
  addImage(images, person.tmdb_image, "Current TMDb Image", "No current TMDb image", person.name);
  if (person.flag_reason) images.append(googleImageSearchTile(person.name));
  const kometaImage = person.kometa_image && { preview_url: person.kometa_image, download_url: person.kometa_image };
  addImage(images, kometaImage, "Kometa Repo Image", "No Kometa Repo image", person.name);
  const variants = person.flag_reason ? (person.kometa_variant_images || []).slice(0, 4) : (person.kometa_variant_images || []);
  variants.forEach((variant) => {
    addImage(images, { preview_url: variant.url, download_url: variant.url }, variant.label, "", person.name);
  });
  const flagReason = document.createElement("aside");
  flagReason.className = "flag-reason";
  if (person.flag_reason) {
    const label = document.createElement("strong");
    label.textContent = "Flag Reason";
    flagReason.append(label, document.createTextNode(person.flag_reason));
  } else flagReason.hidden = true;
  card.append(controls, heading, detail, knownFor, flagReason, images);
  gallery.append(card);
}

function pageLink(number, label, disabled = false) {
  const link = document.createElement(disabled ? "span" : "a");
  link.textContent = label;
  if (!disabled) link.href = `/people/popular?page=${number}`;
  link.className = disabled ? "pagination-disabled" : "secondary-button";
  return link;
}

function pageJumper(currentPage, totalPages) {
  const status = document.createElement("span");
  status.className = "page-jumper";
  status.append("Page ");
  const select = document.createElement("select");
  select.setAttribute("aria-label", "Page number");
  for (let number = 1; number <= totalPages; number += 1) {
    const option = document.createElement("option");
    option.value = number;
    option.textContent = number;
    option.selected = number === currentPage;
    select.append(option);
  }
  select.addEventListener("change", () => { location.href = `/people/popular?page=${select.value}`; });
  status.append(select, ` of ${totalPages}`);
  return status;
}

fetch(`/api/people/popular?page=${page}`).then(async (response) => {
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Unable to load popular people.");
  return data;
}).then(({ people, page: currentPage, total_pages: totalPages }) => {
  gallery.replaceChildren();
  people.forEach(addPerson);
  pagination.replaceChildren(pageLink(currentPage - 1, "← Previous", currentPage === 1), pageJumper(currentPage, totalPages), pageLink(currentPage + 1, "Next →", currentPage === totalPages));
}).catch((error) => { gallery.textContent = error.message; });
