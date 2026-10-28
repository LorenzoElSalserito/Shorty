<script setup>
import { ref } from 'vue'

const props = defineProps({ action: { type: String, required: true } })

const widget = ref(null)
let payload = null

const configuration = JSON.stringify({
  humanInteractionSignature: false,
  hideLogo: false,
  workers: Math.min(4, navigator.hardwareConcurrency || 2),
  minDuration: 300,
})

const onState = (e) => {
  payload = e.detail?.state === 'verified' ? e.detail.payload || payload : null
}

// Returns a fresh one-time payload, solving the proof-of-work if the user has not yet.
const solve = async () => {
  if (payload) return payload
  const res = await widget.value.verify()
  payload = res?.payload || null
  return payload
}

const reset = () => {
  payload = null
  widget.value?.reset()
}

defineExpose({ solve, reset })
</script>

<template>
  <altcha-widget
    ref="widget"
    :challenge="`internal/challenge.php?action=${props.action}`"
    language="it"
    type="checkbox"
    auto="off"
    :configuration="configuration"
    @statechange="onState"
  ></altcha-widget>
</template>
