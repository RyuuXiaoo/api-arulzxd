const express = require("express");

const router = express.Router();

const API =
  "https://raw.githubusercontent.com/arulzzzxd/database/main/quotes/anime.json";

async function getAnime() {
  const res = await fetch(API, {
    headers: {
      "User-Agent": "Mozilla/5.0",
      "Accept": "application/json,text/plain,*/*"
    }
  });

  const text = await res.text();

  if (!res.ok) {
    return {
      ok: false,
      code: res.status,
      data: null,
      error: text
    };
  }

  try {
    return {
      ok: true,
      code: res.status,
      data: JSON.parse(text),
      error: null
    };
  } catch {
    return {
      ok: false,
      code: res.status,
      data: null,
      error: "Invalid JSON"
    };
  }
}

function normalizeData(data) {
  if (Array.isArray(data)) return data;
  if (Array.isArray(data.result)) return data.result;
  if (Array.isArray(data.data)) return data.data;
  if (Array.isArray(data.anime)) return data.anime;
  return [];
}

function pickRandom(list) {
  return list[Math.floor(Math.random() * list.length)];
}

router.get("/", async (req, res) => {
  try {
    const result = await getAnime();

    if (!result.ok) {
      return res.status(result.code).json({
        status: false,
        code: result.code,
        creator: "ArulzXD",
        message: result.error
      });
    }

    const list = normalizeData(result.data);

    if (!list.length) {
      return res.status(404).json({
        status: false,
        code: 404,
        creator: "ArulzXD",
        message: "Data tidak ditemukan."
      });
    }

    const random = pickRandom(list);

    res.json({
      status: true,
      code: 200,
      creator: "ArulzXD",
      result: random
    });

  } catch (err) {
    res.status(500).json({
      status: false,
      code: 500,
      creator: "ArulzXD",
      message: err.message
    });
  }
});

router.status = "ready";
router.type = "free";

module.exports = router;